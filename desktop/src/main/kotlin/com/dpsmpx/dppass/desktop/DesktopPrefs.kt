package com.dpsmpx.dppass.desktop

import com.dpsmpx.dppass.core.ProfileId
import com.dpsmpx.dppass.desktop.ui.ThemeChoice
import java.io.File
import java.io.IOException
import java.nio.file.Files
import java.nio.file.StandardCopyOption
import java.util.Properties

/**
 * Настройки окна ПК — не документ конфигурации (D-06) и не то, что задаёт
 * подписка (D-11): выбранный сервер (D-34) и тема. Файл в каталоге данных
 * (0700); запись — заменой файла целиком.
 */
class DesktopPrefs(private val file: File) {
    private val props = Properties().also { p ->
        try {
            if (file.isFile) file.inputStream().use(p::load)
        } catch (_: IOException) {
            // Не прочиталось — как без настроек: сервер «авто», тема системы.
        }
    }

    var selectedServer: ProfileId?
        get() = props.getProperty(SERVER)?.let(::ProfileId)
        set(value) = put(SERVER, value?.value)

    var theme: ThemeChoice
        get() = props.getProperty(THEME)?.let { v -> ThemeChoice.entries.firstOrNull { it.name == v } } ?: ThemeChoice.AUTO
        set(value) = put(THEME, value.name)

    @Synchronized
    private fun put(key: String, value: String?) {
        if (value == null) props.remove(key) else props.setProperty(key, value)
        try {
            val tmp = File(file.parentFile, file.name + ".tmp")
            tmp.outputStream().use { props.store(it, null) }
            Files.move(tmp.toPath(), file.toPath(), StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE)
        } catch (_: IOException) {
            // Настройка остаётся в памяти до выхода; окно работает и так.
        }
    }

    private companion object {
        const val SERVER = "server"
        const val THEME = "theme"
    }
}
