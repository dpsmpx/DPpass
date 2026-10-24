package com.dpsmpx.dppass.app

import android.content.Context
import android.content.SharedPreferences
import com.dpsmpx.dppass.connection.ServerlessSettings
import com.dpsmpx.dppass.core.Ids
import com.dpsmpx.dppass.core.ProfileId
import com.dpsmpx.dppass.routing.RoutingValidator
import com.dpsmpx.dppass.routing.SplitSites
import com.dpsmpx.dppass.subscriptions.ExpiryReminderSettings

/**
 * Настройки интерфейса (D-34): выбранный сервер или устройство раздачи
 * (D-55), автопереключение (D-58), проверка сети при её смене (D-67),
 * разбиение ClientHello к серверу (D-68), сайты напрямую с разбиением
 * (D-72), режим без сервера (D-73), напоминание о конце подписки
 * (D-76) и открытый экран. Не
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

    /**
     * Список «Напрямую с разбиением» (D-72): текст настройки, запись на
     * строку. Сохраняется только разобранный ([SplitSites.format]); пусто —
     * по умолчанию.
     */
    var splitSitesText: String
        get() = prefs.getString(SPLIT_SITES, "").orEmpty()
        set(value) {
            prefs.edit().putString(SPLIT_SITES, value).apply()
        }

    /** Список в силе. Сохранённый текст всегда разбирается: его записал [SplitSites.format]. */
    fun splitSites(): SplitSites = SplitSites.parse(splitSitesText).valueOrNull() ?: SplitSites.NONE

    /**
     * Без сервера (D-73): остальные сайты, DNS, приложения и свой выбор
     * приложений. Незнакомое значение — выбор по умолчанию
     * ([ServerlessSettings.of]).
     */
    var serverless: ServerlessSettings
        get() = ServerlessSettings.of(
            prefs.getString(SERVERLESS_REST, null),
            prefs.getString(SERVERLESS_DNS, null),
            prefs.getString(SERVERLESS_APPS, null),
            prefs.getString(SERVERLESS_OWN_MODE, null),
            prefs.getStringSet(SERVERLESS_OWN_APPS, null).orEmpty().filterTo(LinkedHashSet(), RoutingValidator::isValidPackage),
        )
        set(value) {
            prefs.edit()
                .putString(SERVERLESS_REST, value.rest.wire)
                .putString(SERVERLESS_DNS, value.dns.wire)
                .putString(SERVERLESS_APPS, value.apps.wire)
                .putString(SERVERLESS_OWN_MODE, value.ownMode.wire)
                .putStringSet(SERVERLESS_OWN_APPS, value.ownApps)
                .apply()
        }

    /** Напоминание о конце подписки (D-76): одна настройка на все подписки. */
    var expiryReminders: ExpiryReminderSettings
        get() = ExpiryReminderSettings.of(
            prefs.getBoolean(EXPIRY_ON, false),
            prefs.getString(EXPIRY_WAY, null),
            prefs.getString(EXPIRY_DAYS, null),
            prefs.getInt(EXPIRY_MINUTE, -1).takeIf { it >= 0 },
        )
        set(value) {
            prefs.edit()
                .putBoolean(EXPIRY_ON, value.enabled)
                .putString(EXPIRY_WAY, value.way.wire)
                .putString(EXPIRY_DAYS, ExpiryReminderSettings.formatDays(value.daysBefore))
                .putInt(EXPIRY_MINUTE, value.minuteOfDay)
                .apply()
        }

    /** О чём уже напомнили (`ExpiryReminder.key`, D-76): по одному разу на порог и срок. */
    var expiryDone: Set<String>
        // Копия: множество из SharedPreferences менять нельзя.
        get() = prefs.getStringSet(EXPIRY_DONE, null).orEmpty().toSet()
        set(value) {
            prefs.edit().putStringSet(EXPIRY_DONE, value).apply()
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
        const val SPLIT_SITES = "split_sites"
        const val SERVERLESS_REST = "serverless_rest"
        const val SERVERLESS_DNS = "serverless_dns"
        const val SERVERLESS_APPS = "serverless_apps"
        const val SERVERLESS_OWN_MODE = "serverless_own_mode"
        const val SERVERLESS_OWN_APPS = "serverless_own_apps"
        const val EXPIRY_ON = "expiry_reminders"
        const val EXPIRY_WAY = "expiry_way"
        const val EXPIRY_DAYS = "expiry_days"
        const val EXPIRY_MINUTE = "expiry_minute"
        const val EXPIRY_DONE = "expiry_done"
    }
}
