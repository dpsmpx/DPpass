package com.dpsmpx.dppass.desktop

import com.dpsmpx.dppass.diagnostics.DiagCode
import com.dpsmpx.dppass.diagnostics.Diagnostic
import com.dpsmpx.dppass.diagnostics.Outcome
import com.dpsmpx.dppass.storage.KeyWrapper
import java.io.File
import java.io.IOException
import java.nio.file.Files
import java.nio.file.attribute.PosixFilePermission

/**
 * Каталоги оболочки ПК. Linux (D-74): данные — `$XDG_DATA_HOME/dppass`
 * (`~/.local/share/dppass`), пакет — [install] (`/usr/lib/dppass`: jar,
 * библиотека ядра, набор геоданных). Windows (D-97, [windows]): данные —
 * `%LOCALAPPDATA%\DPpass`, пакет — каталог распакованного архива.
 */
class DesktopPaths(val data: File, val install: File, val windows: Boolean = false) {
    val state: File get() = File(data, "state")
    val keys: File get() = File(data, "keys")
    val geodata: File get() = File(data, "geodata")
    val library: File get() = File(install, if (windows) "native/dppassxray.dll" else "native/libdppassxray.so")

    /**
     * Каталоги данных — 0700: записи и ключ данных не видны другим
     * пользователям ПК (T7). Каталог с другими правами исправляется, а не
     * принимается молча. На Windows прав POSIX нет: `%LOCALAPPDATA%` и так
     * доступен только владельцу и администраторам, а ключ данных — под
     * DPAPI пользователя (D-97).
     */
    fun prepare(): Outcome<Unit> {
        for (dir in listOf(data, state, keys, geodata)) {
            try {
                if (!dir.isDirectory && !dir.mkdirs()) throw IOException("не создан")
                if (!windows) Files.setPosixFilePermissions(dir.toPath(), OWNER_ONLY)
            } catch (e: IOException) {
                return Outcome.failure(Diagnostic.fromThrowable(DiagCode.STORAGE_WRITE_FAILED, "каталог данных ${dir.path} не подготовлен", e))
            } catch (e: UnsupportedOperationException) {
                return Outcome.failure(Diagnostic.fromThrowable(DiagCode.STORAGE_WRITE_FAILED, "у каталога ${dir.path} нет прав POSIX", e))
            }
        }
        return Outcome.Success(Unit)
    }

    companion object {
        val OWNER_ONLY: Set<PosixFilePermission> = setOf(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE, PosixFilePermission.OWNER_EXECUTE)

        /** `$XDG_DATA_HOME` — только абсолютный путь (спецификация XDG), иначе `~/.local/share`. */
        fun dataDir(env: Map<String, String>, home: String): File {
            val xdg = env["XDG_DATA_HOME"]?.takeIf { it.startsWith("/") }
            return File(xdg ?: "$home/.local/share", "dppass")
        }

        /**
         * `%LOCALAPPDATA%` — только абсолютный путь с буквой диска (как его
         * задаёт Windows), иначе `~\AppData\Local` (D-97).
         */
        fun windowsDataDir(env: Map<String, String>, home: String): File {
            val local = env["LOCALAPPDATA"]?.takeIf { WINDOWS_ABSOLUTE.matches(it) }
            return File(local ?: "$home\\AppData\\Local", "DPpass")
        }

        private val WINDOWS_ABSOLUTE = Regex("""^[A-Za-z]:[\\/].*""")

        /** Корень пакета — каталог над `lib/`, где лежит jar оболочки. */
        fun installDir(jar: File): File = jar.absoluteFile.parentFile.parentFile
    }
}

/**
 * Ключ данных без обёртки (D-74, T7): Keystore на Linux нет, а Secret
 * Service — D-Bus и новая зависимость. Ключ лежит файлом в каталоге 0700:
 * от других пользователей его защищают права, от программ того же
 * пользователя — нет, и это записано, а не скрыто.
 */
class PlainKeyWrapper : KeyWrapper {
    override fun exists(): Boolean = true

    override fun create() = Unit

    override fun wrap(plain: ByteArray): ByteArray = plain.copyOf()

    override fun unwrap(sealed: ByteArray): ByteArray = sealed.copyOf()
}
