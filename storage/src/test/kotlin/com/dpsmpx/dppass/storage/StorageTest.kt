package com.dpsmpx.dppass.storage

import com.dpsmpx.dppass.core.ManualClock
import com.dpsmpx.dppass.diagnostics.DiagCode
import com.dpsmpx.dppass.diagnostics.Diagnostic
import com.dpsmpx.dppass.diagnostics.Outcome
import java.nio.file.Files
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

class StorageTest {
    @Test
    fun concurrentWritersUseIndependentTemporaryFiles() {
        val dir = Files.createTempDirectory("dppass-store-race").toFile()
        try {
            val start = java.util.concurrent.CountDownLatch(1)
            val pool = java.util.concurrent.Executors.newFixedThreadPool(4)
            try {
                val jobs = (1..4).map { n ->
                    pool.submit<Boolean> {
                        start.await()
                        val store = FileBlobStore(dir)
                        (1..30).all { store.write("shared/key", ByteArray(8192) { n.toByte() }) is Outcome.Success }
                    }
                }
                start.countDown()
                assertTrue(jobs.all { it.get() })
                val data = FileBlobStore(dir).read("shared/key").valueOrNull()!!
                assertEquals(8192, data.size)
                assertTrue(data.all { it == data[0] })
                assertFalse(dir.walkTopDown().any { it.name.endsWith(".tmp") })
            } finally {
                pool.shutdownNow()
            }
        } finally {
            dir.deleteRecursively()
        }
    }

    private val key = KeyProvider { Outcome.Success(ByteArray(32) { it.toByte() }) }

    @Test
    fun fileStoreWritesAtomicallyAndReadsBack() {
        val dir = Files.createTempDirectory("dppass-store").toFile()
        val s = FileBlobStore(dir)
        assertTrue(s.write("activation/state", "v1".toByteArray()).isSuccess)
        assertTrue(s.write("activation/state", "v2".toByteArray()).isSuccess)
        assertContentEquals("v2".toByteArray(), s.read("activation/state").valueOrNull())
        assertEquals(listOf("activation/state"), s.keys("activation/").valueOrNull())
        assertFalse(dir.walkTopDown().any { it.name.endsWith(".tmp") }, "временный файл не должен оставаться")
        assertNull(s.read("missing/key").valueOrNull())
        dir.deleteRecursively()
    }

    @Test
    fun badKeysAreRefused() {
        val s = InMemoryBlobStore()
        for (k in listOf("../etc/passwd", "/abs", "UPPER", "a//b", "")) {
            assertEquals(DiagCode.STORAGE_KEY_INVALID, s.write(k, ByteArray(1)).errors.single().code, k)
        }
    }

    @Test
    fun encryptedStoreHasNoPlaintextAndDetectsTampering() {
        val raw = InMemoryBlobStore()
        val enc = EncryptingBlobStore(raw, key)
        val secret = "vless-uuid 00000000-0000-4000-8000-000000000001"
        enc.write("activation/state", secret.toByteArray())
        val onDisk = raw.rawSnapshot().getValue("activation/state")
        assertFalse(String(onDisk, Charsets.ISO_8859_1).contains("00000000-0000"))
        assertEquals(secret, String(enc.read("activation/state").valueOrNull()!!))

        onDisk[onDisk.size - 1] = (onDisk[onDisk.size - 1].toInt() xor 1).toByte()
        raw.write("activation/state", onDisk)
        assertEquals(DiagCode.STORAGE_CORRUPTED, enc.read("activation/state").errors.single().code)
    }

    @Test
    fun recordCannotBeMovedUnderAnotherKey() {
        val raw = InMemoryBlobStore()
        val enc = EncryptingBlobStore(raw, key)
        enc.write("a/one", "x".toByteArray())
        raw.write("a/two", raw.rawSnapshot().getValue("a/one"))
        assertEquals(DiagCode.STORAGE_CORRUPTED, enc.read("a/two").errors.single().code)
    }

    @Test
    fun quarantineKeepsOriginalAndReason() {
        val store = InMemoryBlobStore()
        val q = Quarantine(store, ManualClock(5))
        val k = q.keep("activation", "broken".toByteArray(), Diagnostic.error(DiagCode.STORAGE_CORRUPTED, "bad"))
        assertEquals<List<String>?>(listOf(k.valueOrNull()!!), q.list().valueOrNull())
        assertContentEquals("broken".toByteArray(), store.read("${k.valueOrNull()}.data").valueOrNull())
    }
}

/** Ключ-обёртка для тестов: AES-GCM в памяти вместо Keystore, с отказами по заказу. */
private class FakeKeyWrapper : KeyWrapper {
    var kek: SecretKey? = null
    var fault: Exception? = null
    var creates = 0

    override fun exists(): Boolean {
        fault?.let { throw it }
        return kek != null
    }

    override fun create() {
        fault?.let { throw it }
        if (kek == null) {
            creates++
            kek = KeyGenerator.getInstance("AES").apply { init(256) }.generateKey()
        }
    }

    override fun wrap(plain: ByteArray): ByteArray {
        fault?.let { throw it }
        val c = Cipher.getInstance("AES/GCM/NoPadding")
        c.init(Cipher.ENCRYPT_MODE, kek)
        return c.iv + c.doFinal(plain)
    }

    override fun unwrap(sealed: ByteArray): ByteArray {
        fault?.let { throw it }
        val c = Cipher.getInstance("AES/GCM/NoPadding")
        c.init(Cipher.DECRYPT_MODE, kek, GCMParameterSpec(128, sealed, 0, 12))
        return c.doFinal(sealed, 12, sealed.size - 12)
    }
}

/** Хранилище, запись в которое можно временно «сломать». */
private class FailingWrites(private val inner: BlobStore) : BlobStore by inner {
    var fail = false

    override fun write(key: String, bytes: ByteArray): Outcome<Unit> =
        if (fail) Outcome.failure(DiagCode.STORAGE_WRITE_FAILED, "запись «$key» не прошла") else inner.write(key, bytes)
}

/** Ключ данных хранилища (D-19): отказы — свои коды, а не «порча записи»; ничего не теряется молча. */
class DataKeyTest {
    private val wrapper = FakeKeyWrapper()
    private val keys = InMemoryBlobStore()
    private val data = InMemoryBlobStore()
    private fun provider(store: BlobStore = keys) = WrappedKeyProvider(store, wrapper, dataPresent = { StorageReset.hasData(data) })

    @Test
    fun firstUseCreatesKeyOnceAndKeepsItOnlyWrapped() {
        val dir = Files.createTempDirectory("dppass-keys").toFile()
        val onDisk = FileBlobStore(dir)
        val k = provider(onDisk).key().valueOrNull()!!
        assertEquals(32, k.size)
        val sealed = onDisk.read(WrappedKeyProvider.KEY).valueOrNull()!!
        assertFalse(sealed.toList().windowed(32).any { it == k.toList() }, "на диске — только обёрнутый ключ")
        assertFalse(dir.walkTopDown().any { it.name.endsWith(".tmp") }, "ключ записан атомарно, без хвостов")
        assertContentEquals(k, provider(onDisk).key().valueOrNull(), "после перезапуска — тот же ключ")
        assertEquals(1, wrapper.creates)
        dir.deleteRecursively()
    }

    @Test
    fun keystoreHiccupIsUnavailableNotCorruptionAndIsRetried() {
        EncryptingBlobStore(data, provider()).write("activation/state", "state".toByteArray())
        val sealed = keys.rawSnapshot().getValue(WrappedKeyProvider.KEY)
        val p = provider() // новый процесс: ключ не в памяти
        val enc = EncryptingBlobStore(data, p)
        wrapper.fault = IllegalStateException("Keystore занят")
        assertEquals(DiagCode.STORAGE_DATA_KEY_UNAVAILABLE, enc.read("activation/state").errors.single().code)
        assertEquals(DiagCode.STORAGE_DATA_KEY_UNAVAILABLE, enc.write("activation/next", "x".toByteArray()).errors.single().code)
        assertNull(data.rawSnapshot()["activation/next"], "без ключа ничего не записано")
        assertContentEquals(sealed, keys.rawSnapshot().getValue(WrappedKeyProvider.KEY), "обёрнутый ключ не тронут")
        wrapper.fault = null
        assertEquals("state", String(enc.read("activation/state").valueOrNull()!!), "отказ не запомнен: следующий вызов работает")
    }

    @Test
    fun lostOrDamagedKeyIsLostAndNoNewKeyReplacesIt() {
        provider().key()
        val sealed = keys.rawSnapshot().getValue(WrappedKeyProvider.KEY)
        val kek = wrapper.kek

        wrapper.kek = null // ключ Keystore утрачен
        assertEquals(DiagCode.STORAGE_DATA_KEY_LOST, provider().key().errors.single().code)

        wrapper.kek = kek
        wrapper.fault = KeyWrapper.KeyLost("ключ Keystore необратимо недействителен")
        assertEquals(DiagCode.STORAGE_DATA_KEY_LOST, provider().key().errors.single().code)
        wrapper.fault = null

        keys.write(WrappedKeyProvider.KEY, sealed.copyOf().also { it[it.size - 1] = (it[it.size - 1].toInt() xor 1).toByte() })
        assertEquals(DiagCode.STORAGE_DATA_KEY_LOST, provider().key().errors.single().code)

        assertEquals(1, wrapper.creates, "новый ключ взамен утраченного молча не создаётся")
    }

    @Test
    fun missingWrappedKeyWithStoredDataIsLost() {
        data.write("activation/state", ByteArray(40))
        assertEquals(DiagCode.STORAGE_DATA_KEY_LOST, provider().key().errors.single().code)
        assertTrue(keys.rawSnapshot().isEmpty(), "новый ключ не создан: записи стали бы нечитаемыми без следа")
        assertEquals(0, wrapper.creates)
    }

    @Test
    fun keyThatWasNotSavedIsNeverUsed() {
        val failing = FailingWrites(keys).apply { fail = true }
        val p = provider(failing)
        assertEquals(DiagCode.STORAGE_DATA_KEY_UNAVAILABLE, p.key().errors.single().code)
        failing.fail = false
        val k = p.key().valueOrNull()!!
        assertContentEquals(k, provider().key().valueOrNull(), "используется только сохранённый ключ")
    }

    @Test
    fun resetMovesEverythingAsideByteForByteAndStartsFresh() {
        val enc = EncryptingBlobStore(data, provider())
        enc.write("activation/state", "old".toByteArray())
        enc.write("quarantine/activation-1.data", "q".toByteArray())
        val records = data.rawSnapshot()
        val sealed = keys.rawSnapshot().getValue(WrappedKeyProvider.KEY)

        wrapper.kek = null // ключ утрачен: сохранённое не прочитать
        val p = provider()
        val after = EncryptingBlobStore(data, p)
        assertEquals(DiagCode.STORAGE_DATA_KEY_LOST, after.read("activation/state").errors.single().code)

        assertEquals("lost/42", StorageReset(data, p, ManualClock(42)).reset().valueOrNull())
        assertEquals(records.keys.map { "lost/42/$it" }.toSet(), data.rawSnapshot().keys)
        records.forEach { (k, v) -> assertContentEquals(v, data.rawSnapshot().getValue("lost/42/$k"), "отложено как есть: $k") }
        assertContentEquals(sealed, keys.rawSnapshot().getValue("lost/42/${WrappedKeyProvider.KEY}"))

        assertNull(after.read("activation/state").valueOrNull(), "начато с чистого")
        assertTrue(after.write("activation/state", "new".toByteArray()).isSuccess)
        assertEquals("new", String(after.read("activation/state").valueOrNull()!!))
        assertFalse(StorageReset.hasData(InMemoryBlobStore().apply { write("lost/1/a", ByteArray(1)) }), "отложенное — не данные")
    }
}
