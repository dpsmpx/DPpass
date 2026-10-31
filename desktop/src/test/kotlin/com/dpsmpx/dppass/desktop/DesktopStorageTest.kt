package com.dpsmpx.dppass.desktop

import com.dpsmpx.dppass.diagnostics.Outcome
import com.dpsmpx.dppass.storage.EncryptingBlobStore
import com.dpsmpx.dppass.storage.FileBlobStore
import com.dpsmpx.dppass.storage.StorageReset
import com.dpsmpx.dppass.storage.WrappedKeyProvider
import java.io.File
import java.nio.file.Files
import java.nio.file.attribute.PosixFilePermissions
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.fail

/** Хранение оболочки Linux (D-74, T7): каталоги 0700, ключ данных без обёртки, записи зашифрованы. */
class DesktopStorageTest {
    private fun tmp(): File = Files.createTempDirectory("dppass-desktop").toFile().also { it.deleteOnExit() }

    @Test
    fun secondDpPassOnTheSameDataIsRefusedUntilTheFirstExits() {
        // Ярлык через задачу и автозапуск (D-100) легко запускают DPpass дважды: второй хранилище не трогает.
        val data = tmp()
        val first = assertNotNull(DesktopLock.acquire(data))
        assertNull(DesktopLock.acquire(data), "замок занят — второй экземпляр не запускается")
        first.close()
        DesktopLock.acquire(data)?.close() ?: fail("замок не освободился после выхода первого")
    }

    @Test
    fun dataDirectoriesAreOwnerOnlyEvenIfTheyExisted() {
        val root = tmp()
        val paths = DesktopPaths(File(root, "dppass"), root)
        // Каталог уже был — с правами для всех: исправляется, а не принимается молча.
        paths.state.mkdirs()
        Files.setPosixFilePermissions(paths.state.toPath(), PosixFilePermissions.fromString("rwxr-xr-x"))
        assertIs<Outcome.Success<Unit>>(paths.prepare())
        for (dir in listOf(paths.data, paths.state, paths.keys, paths.geodata)) {
            assertEquals("rwx------", PosixFilePermissions.toString(Files.getPosixFilePermissions(dir.toPath())), dir.path)
        }
    }

    @Test
    fun recordsAreEncryptedWithAPlainDataKeyFile() {
        val root = tmp()
        val paths = DesktopPaths(File(root, "dppass"), root)
        assertIs<Outcome.Success<Unit>>(paths.prepare())
        fun store(): EncryptingBlobStore {
            val data = FileBlobStore(paths.state)
            val keys = WrappedKeyProvider(FileBlobStore(paths.keys), PlainKeyWrapper(), dataPresent = { StorageReset.hasData(data) })
            return EncryptingBlobStore(data, keys)
        }
        val secret = "vless-uuid-00000000-0000-4000-8000-000000000001".encodeToByteArray()
        assertIs<Outcome.Success<Unit>>(store().write("subscriptions", secret))
        // На диске — не открытый текст; новый процесс (новые объекты) читает тем же ключом из файла.
        val onDisk = File(paths.state, "subscriptions").readBytes()
        assertFalse(onDisk.decodeToString().contains("vless-uuid"))
        assertContentEquals(secret, store().read("subscriptions").valueOrNull())
    }

    @Test
    fun xdgDataHomeOnlyWhenAbsolute() {
        assertEquals(File("/data/x/dppass"), DesktopPaths.dataDir(mapOf("XDG_DATA_HOME" to "/data/x"), "/home/u"))
        assertEquals(File("/home/u/.local/share/dppass"), DesktopPaths.dataDir(mapOf("XDG_DATA_HOME" to "relative"), "/home/u"))
        assertEquals(File("/home/u/.local/share/dppass"), DesktopPaths.dataDir(emptyMap(), "/home/u"))
    }

    @Test
    fun installDirIsAboveLib() {
        assertEquals(File("/usr/lib/dppass"), DesktopPaths.installDir(File("/usr/lib/dppass/lib/desktop.jar")))
        assertEquals(File("/usr/lib/dppass/native/libdppassxray.so"), DesktopPaths(File("/d"), File("/usr/lib/dppass")).library)
    }
}
