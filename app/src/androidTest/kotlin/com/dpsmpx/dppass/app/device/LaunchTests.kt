package com.dpsmpx.dppass.app.device

import android.view.WindowManager
import com.dpsmpx.dppass.R
import com.dpsmpx.dppass.app.ui.Host

/** Запуск (D-75): вкладки на месте, окно закрыто от снимков экрана (T9). */
object LaunchTests : DeviceSuite {
    override val name = "Launch"

    /** Четыре вкладки; граф приложения собирается в фоне — тесты ждут его здесь. */
    val TABS = listOf(R.string.tab_connect, R.string.tab_servers, R.string.tab_subscriptions, R.string.tab_settings)

    override val cases = listOf(
        DeviceCase("fourTabsWithLabels") { d ->
            val a = d.launch()
            d.waitUntil("граф приложения собран") { (a as Host).graph != null }
            for (tab in TABS) {
                val label = d.context.getString(tab)
                expect(d.find(a, label) != null) { "нет вкладки «$label» с подписью для TalkBack" }
            }
        },
        DeviceCase("windowIsSecure") { d ->
            val a = d.launch()
            val flags = d.main { a.window.attributes.flags }
            expect(flags and WindowManager.LayoutParams.FLAG_SECURE != 0) { "окно без FLAG_SECURE: экран попадёт в снимки и «Недавние» (T9)" }
        },
    )
}
