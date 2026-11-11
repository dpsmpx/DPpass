package com.dpsmpx.dppass.storage

import com.dpsmpx.dppass.core.Clock
import com.dpsmpx.dppass.diagnostics.DiagCode
import com.dpsmpx.dppass.diagnostics.Diagnostic
import com.dpsmpx.dppass.diagnostics.Outcome
import java.io.File
import java.io.IOException
import java.nio.file.AtomicMoveNotSupportedException
import java.nio.file.Files
import java.nio.file.StandardCopyOption
import java.security.SecureRandom
import javax.crypto.AEADBadTagException
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * Хранилище байтов по ключу (D-19). Запись — атомарная: читатель видит
 * либо старое значение, либо новое целиком, но никогда не половину.
 * Ключ — `[a-z0-9._-]` сегменты через `/`.
 */
interface BlobStore {
    fun read(key: String): Outcome<ByteArray?>
    fun write(key: String, bytes: ByteArray): Outcome<Unit>
    fun delete(key: String): Outcome<Unit>
    fun keys(prefix: String): Outcome<List<String>>
}

object StorageKeys {
    private val KEY = Regex("""[a-z0-9][a-z0-9._-]{0,63}(/[a-z0-9][a-z0-9._-]{0,63}){0,7}""")

    fun isValid(key: String): Boolean = KEY.matches(key) && ".." !in key

    fun check(key: String): Diagnostic? =
        if (isValid(key)) null else Diagnostic.error(DiagCode.STORAGE_KEY_INVALID, "недопустимый ключ хранилища")
}

class InMemoryBlobStore : BlobStore {
    private val map = sortedMapOf<String, ByteArray>()

    @Synchronized
    override fun read(key: String): Outcome<ByteArray?> =
        StorageKeys.check(key)?.let { Outcome.failure(it) } ?: Outcome.Success(map[key]?.copyOf())

    @Synchronized
    override fun write(key: String, bytes: ByteArray): Outcome<Unit> {
        StorageKeys.check(key)?.let { return Outcome.failure(it) }
        map[key] = bytes.copyOf()
        return Outcome.Success(Unit)
    }

    @Synchronized
    override fun delete(key: String): Outcome<Unit> {
        StorageKeys.check(key)?.let { return Outcome.failure(it) }
        map.remove(key)
        return Outcome.Success(Unit)
    }

    @Synchronized
    override fun keys(prefix: String): Outcome<List<String>> = Outcome.Success(map.keys.filter { it.startsWith(prefix) })

    /** Сырые байты — только для тестов (проверка, что на «диске» нет открытого текста). */
    @Synchronized
    fun rawSnapshot(): Map<String, ByteArray> = map.mapValues { it.value.copyOf() }
}

/**
 * Файлы в каталоге. Атомарность: запись во временный файл, `fsync`,
 * переименование поверх (`ATOMIC_MOVE`). Обрыв посередине оставляет
 * прежний файл нетронутым.
 */
class FileBlobStore(private val root: File) : BlobStore {
    override fun read(key: String): Outcome<ByteArray?> {
        StorageKeys.check(key)?.let { return Outcome.failure(it) }
        val f = File(root, key)
        return try {
            Outcome.Success(if (f.isFile) f.readBytes() else null)
        } catch (e: IOException) {
            Outcome.failure(Diagnostic.fromThrowable(DiagCode.STORAGE_READ_FAILED, "не прочитан ключ «$key»", e))
        }
    }

    override fun write(key: String, bytes: ByteArray): Outcome<Unit> {
        StorageKeys.check(key)?.let { return Outcome.failure(it) }
        val target = File(root, key)
        var temporary: File? = null
        return try {
            target.parentFile.mkdirs()
            val tmp = Files.createTempFile(target.parentFile.toPath(), ".${target.name}.", ".tmp").toFile()
            temporary = tmp
            tmp.outputStream().use { out ->
                out.write(bytes)
                out.fd.sync()
            }
            try {
                Files.move(tmp.toPath(), target.toPath(), StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING)
            } catch (e: AtomicMoveNotSupportedException) {
                tmp.delete()
                return Outcome.failure(Diagnostic.fromThrowable(DiagCode.STORAGE_WRITE_FAILED, "файловая система не умеет атомарную замену", e))
            }
            Outcome.Success(Unit)
        } catch (e: IOException) {
            Outcome.failure(Diagnostic.fromThrowable(DiagCode.STORAGE_WRITE_FAILED, "не записан ключ «$key»", e))
        } finally {
            temporary?.delete()
        }
    }

    override fun delete(key: String): Outcome<Unit> {
        StorageKeys.check(key)?.let { return Outcome.failure(it) }
        File(root, key).delete()
        return Outcome.Success(Unit)
    }

    override fun keys(prefix: String): Outcome<List<String>> {
        if (!root.isDirectory) return Outcome.Success(emptyList())
        val out = root.walkTopDown().filter { it.isFile && !it.name.startsWith(".") }
            .map { it.relativeTo(root).invariantSeparatorsPath }
            .filter { it.startsWith(prefix) }
            .sorted()
            .toList()
        return Outcome.Success(out)
    }
}

/**
 * Источник ключа шифрования. На Android — [WrappedKeyProvider] с ключом
 * Keystore (`app/`); в тестах — фиксированный ключ. Отказ — значение
 * (`STORAGE_DATA_KEY_UNAVAILABLE`, `STORAGE_DATA_KEY_LOST`), а не
 * исключение: ключ бывает временно недоступен (D-22).
 */
fun interface KeyProvider {
    /** 32 байта ключа AES-256. */
    fun key(): Outcome<ByteArray>
}

/**
 * Шифрование поверх любого [BlobStore]: AES-256-GCM, случайный nonce на
 * запись, ключ хранилища как дополнительные данные (запись нельзя
 * переложить под другой ключ). На диске не бывает открытых секретов
 * (D-19); подмена или порча записи — `STORAGE_CORRUPTED`, а не мусор в
 * IR. Отказ ключа — его собственный код от [KeyProvider]: ключ один на
 * всё хранилище, и его сбой — не порча одной записи.
 */
class EncryptingBlobStore(
    private val inner: BlobStore,
    private val keys: KeyProvider,
    private val random: SecureRandom = SecureRandom(),
) : BlobStore {
    override fun read(key: String): Outcome<ByteArray?> {
        val raw = when (val r = inner.read(key)) {
            is Outcome.Failure -> return r
            is Outcome.Success -> r.value ?: return Outcome.Success(null)
        }
        if (raw.size < HEADER + NONCE + TAG_BYTES || raw[0] != VERSION) {
            return Outcome.failure(DiagCode.STORAGE_CORRUPTED, "запись «$key» повреждена или не того формата")
        }
        val dataKey = when (val k = keys.key()) {
            is Outcome.Failure -> return k
            is Outcome.Success -> k.value
        }
        return try {
            val cipher = Cipher.getInstance(TRANSFORMATION)
            cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(dataKey, "AES"), GCMParameterSpec(TAG_BYTES * 8, raw, HEADER, NONCE))
            cipher.updateAAD(key.toByteArray(Charsets.UTF_8))
            Outcome.Success(cipher.doFinal(raw, HEADER + NONCE, raw.size - HEADER - NONCE))
        } catch (e: AEADBadTagException) {
            Outcome.failure(DiagCode.STORAGE_CORRUPTED, "запись «$key» не прошла проверку целостности")
        } catch (e: java.security.GeneralSecurityException) {
            Outcome.failure(Diagnostic.fromThrowable(DiagCode.STORAGE_READ_FAILED, "не расшифрована запись «$key»", e))
        }
    }

    override fun write(key: String, bytes: ByteArray): Outcome<Unit> {
        StorageKeys.check(key)?.let { return Outcome.failure(it) }
        val dataKey = when (val k = keys.key()) {
            is Outcome.Failure -> return k
            is Outcome.Success -> k.value
        }
        val nonce = ByteArray(NONCE).also(random::nextBytes)
        val sealed = try {
            val cipher = Cipher.getInstance(TRANSFORMATION)
            cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(dataKey, "AES"), GCMParameterSpec(TAG_BYTES * 8, nonce))
            cipher.updateAAD(key.toByteArray(Charsets.UTF_8))
            cipher.doFinal(bytes)
        } catch (e: java.security.GeneralSecurityException) {
            return Outcome.failure(Diagnostic.fromThrowable(DiagCode.STORAGE_WRITE_FAILED, "не зашифрована запись «$key»", e))
        }
        return inner.write(key, byteArrayOf(VERSION) + nonce + sealed)
    }

    override fun delete(key: String): Outcome<Unit> = inner.delete(key)

    override fun keys(prefix: String): Outcome<List<String>> = inner.keys(prefix)

    private companion object {
        const val TRANSFORMATION = "AES/GCM/NoPadding"
        const val VERSION: Byte = 1
        const val HEADER = 1
        const val NONCE = 12
        const val TAG_BYTES = 16
    }
}

/**
 * Карантин: неподдержанный или повреждённый документ сохраняется как
 * есть, с причиной, и **не заменяется** конфигурацией по умолчанию
 * (D-06). Пользователь может забрать исходник и разобраться.
 */
class Quarantine(private val store: BlobStore, private val clock: Clock) {
    fun keep(kind: String, bytes: ByteArray, reason: Diagnostic): Outcome<String> {
        val key = "quarantine/$kind-${clock.nowMillis()}"
        return when (val w = store.write("$key.data", bytes)) {
            is Outcome.Failure -> w
            is Outcome.Success -> when (val r = store.write("$key.reason", reason.render().toByteArray(Charsets.UTF_8))) {
                is Outcome.Failure -> r
                is Outcome.Success -> Outcome.Success(key)
            }
        }
    }

    fun list(): Outcome<List<String>> = when (val k = store.keys("quarantine/")) {
        is Outcome.Failure -> k
        is Outcome.Success -> Outcome.Success(k.value.filter { it.endsWith(".data") }.map { it.removeSuffix(".data") })
    }
}
