package com.dpsmpx.dppass.app

import android.content.Context
import android.content.SharedPreferences
import com.dpsmpx.dppass.core.Ids
import com.dpsmpx.dppass.core.ProfileId

/**
 * Настройки интерфейса (D-34): выбранный сервер или устройство раздачи
 * (D-55), автопереключение (D-58), проверка сети при её смене (D-67),
 * разбиение ClientHello к серверу (D-68) и открытый экран. Не
 * секреты — id профиля подписки не раскрывает ссылку (`CONFIG_FORMAT.md`,
 * §6); резервных копий у приложения нет (`allowBackup=false`).
 */
class AppPrefs(context: Context) {
    private val prefs: SharedPreferences = context.applicationContext.getSharedPreferences(FILE, Context.MODE_PRIVATE)

    /** Сервер, выбранный пользователем (D-34); null — «автоматически» (D-15). */
    var selectedServer: ProfileId?
        get() = prefs.getString(SELECTED, null)?.takeIf(Ids::isValid)?.let(::ProfileId)
        set(value) {
            prefs.edit().apply { if (value == null) remove(SELECTED) else putString(SELECTED, value.value) }.apply()
        }

    /**
     * Устройство раздачи, выбранное пользователем (D-55): id из списка
     * устройств; null — подключение к серверам подписки, как обычно.
     */
    var selectedRelay: String?
        get() = prefs.getString(RELAY, null)
        set(value) {
            prefs.edit().apply { if (value == null) remove(RELAY) else putString(RELAY, value) }.apply()
        }

    /**
     * «Автопереключение сервера» (D-58): согласие заранее заменять выбранный
     * сервер, когда он перестал отвечать. Выключено — DPpass спрашивает.
     */
    var autoSwitch: Boolean
        get() = prefs.getBoolean(AUTO_SWITCH, false)
        set(value) {
            prefs.edit().putBoolean(AUTO_SWITCH, value).apply()
        }

    /**
     * «Проверять сеть при её смене» (D-67): пока туннель поднят, после смены
     * сети DPpass сам проверяет новую. Включено по умолчанию — выбор автора
     * 18.10.2026; выключено — только по кнопке, как D-60.
     */
    var checkOnNetworkChange: Boolean
        get() = prefs.getBoolean(CHECK_ON_CHANGE, true)
        set(value) {
            prefs.edit().putBoolean(CHECK_ON_CHANGE, value).apply()
        }

    /**
     * «Разбивать начало соединения с сервером» (D-68): TLS ClientHello к
     * серверу — на части по записям TLS и сегментам TCP. Выключено по
     * умолчанию: помогает против части фильтров по имени, но само по себе
     * заметно и добавляет время к подключению.
     */
    var splitClientHello: Boolean
        get() = prefs.getBoolean(SPLIT_CLIENT_HELLO, false)
        set(value) {
            prefs.edit().putBoolean(SPLIT_CLIENT_HELLO, value).apply()
        }

    var tab: Int
        get() = prefs.getInt(TAB, 0)
        set(value) {
            prefs.edit().putInt(TAB, value).apply()
        }

    private companion object {
        const val FILE = "ui"
        const val SELECTED = "selected_server"
        const val TAB = "tab"
        const val RELAY = "selected_relay"
        const val AUTO_SWITCH = "auto_switch"
        const val CHECK_ON_CHANGE = "check_on_network_change"
        const val SPLIT_CLIENT_HELLO = "split_client_hello"
    }
}
