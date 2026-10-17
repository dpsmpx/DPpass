package com.dpsmpx.dppass.app

import android.content.Context
import android.content.SharedPreferences
import com.dpsmpx.dppass.core.Ids
import com.dpsmpx.dppass.core.ProfileId

/**
 * Настройки интерфейса (D-34): выбранный сервер или устройство раздачи
 * (D-55) и открытый экран. Не
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
    }
}
