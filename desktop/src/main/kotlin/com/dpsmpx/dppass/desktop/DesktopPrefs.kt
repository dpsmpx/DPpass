package com.dpsmpx.dppass.desktop

import com.dpsmpx.dppass.connection.ServerlessSettings
import com.dpsmpx.dppass.core.ProfileId
import com.dpsmpx.dppass.desktop.ui.ThemeChoice
import com.dpsmpx.dppass.routing.SplitSites
import java.io.File
import java.io.IOException
import java.nio.file.Files
import java.nio.file.StandardCopyOption
import java.util.Properties

/**
 * Настройки окна ПК — не документ конфигурации (D-06) и не то, что задаёт
 * подписка (D-11): выбранный сервер (D-34), автопереключение (D-58, D-78),
 * проверка сети при её смене (D-80), разбиение ClientHello (D-81), сайты
 * напрямую с разбиением (D-82), без сервера (D-83) и тема. Файл в каталоге данных (0700); запись — заменой файла целиком. Один
 * объект на процесс: окно и сеанс пишут через него.
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

    /** «Автопереключение сервера» (D-58): согласие заранее заменять выбранный сервер, когда он перестал отвечать. */
    var autoSwitch: Boolean
        get() = props.getProperty(AUTO_SWITCH) == "true"
        set(value) = put(AUTO_SWITCH, value.toString())

    /** «Проверять сеть при её смене» (D-67, D-80): включено по умолчанию, как на Android; выключено — только по кнопке. */
    var checkOnNetworkChange: Boolean
        get() = props.getProperty(CHECK_ON_CHANGE) != "false"
        set(value) = put(CHECK_ON_CHANGE, value.toString())

    /**
     * «Разбивать начало соединения с сервером» (D-68, D-81): TLS ClientHello к
     * серверу — частями. Выключено по умолчанию, как на Android.
     */
    var splitClientHello: Boolean
        get() = props.getProperty(SPLIT_CLIENT_HELLO) == "true"
        set(value) = put(SPLIT_CLIENT_HELLO, value.toString())

    /**
     * Список «Напрямую с разбиением» (D-72, D-82): текст настройки, запись на
     * строку. Сохраняется только разобранный ([SplitSites.format]).
     */
    var splitSitesText: String
        get() = props.getProperty(SPLIT_SITES).orEmpty()
        set(value) = put(SPLIT_SITES, value.ifEmpty { null })

    /** Список в силе. Сохранённый текст разбирается всегда: его записал [SplitSites.format]; испорчен — пустой. */
    fun splitSites(): SplitSites = SplitSites.parse(splitSitesText).valueOrNull() ?: SplitSites.NONE

    /**
     * Без сервера (D-73, D-83): остальные сайты и DNS. Выбора приложений на
     * ПК нет — программы не различаются (D-74): туннель для всех.
     */
    var serverless: ServerlessSettings
        get() = ServerlessSettings.of(props.getProperty(SERVERLESS_REST), props.getProperty(SERVERLESS_DNS), null, null, emptySet())
        set(value) {
            put(SERVERLESS_REST, value.rest.wire)
            put(SERVERLESS_DNS, value.dns.wire)
        }

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
        const val AUTO_SWITCH = "auto_switch"
        const val CHECK_ON_CHANGE = "check_on_network_change"
        const val SPLIT_CLIENT_HELLO = "split_client_hello"
        const val SPLIT_SITES = "split_sites"
        const val SERVERLESS_REST = "serverless_rest"
        const val SERVERLESS_DNS = "serverless_dns"
    }
}
