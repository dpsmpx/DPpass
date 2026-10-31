package com.dpsmpx.dppass.app.paths

import android.app.NotificationManager
import android.widget.NumberPicker
import com.dpsmpx.dppass.R
import com.dpsmpx.dppass.app.UsageAlerts
import com.dpsmpx.dppass.app.device.expect
import com.dpsmpx.dppass.app.ui.Formats
import com.dpsmpx.dppass.connection.UsageBytes
import com.dpsmpx.dppass.network.NetworkType
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.Shadows.shadowOf
import org.robolectric.annotation.Config

/**
 * Ключевой путь «учёт трафика» (D-92): счёт через сервер по сетям — на
 * экране «Подключение» и в «Трафике через сервер»; порог мобильной сети и
 * день начала периода — из экрана; пройденный порог — уведомление; сброс —
 * с подтверждением, счёт с нуля.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [26, 29, 36])
class UsagePathTest {
    @Test
    fun countsShowPerNetworkAndThresholdNotifies() {
        Act().use { act ->
            val c = act.context
            val a = act.launch()
            val usage = act.graph(a).core.usage
            usage.record(UsageBytes(GIB / 4, 2 * GIB - GIB / 4), NetworkType.MOBILE)
            usage.record(UsageBytes(0, GIB / 2), NetworkType.WIFI)
            act.tap(a, c.getString(R.string.tab_servers))
            act.tap(a, c.getString(R.string.tab_connect))
            val units = c.resources.getStringArray(R.array.units_bytes).toList()
            val locale = c.resources.configuration.locales[0]
            fun bytes(n: Long) = Formats.bytes(n, units, locale)
            act.waitFor(a, bytes(GIB * 5 / 2))

            act.tap(a, c.getString(R.string.usage_title))
            act.waitFor(a, c.getString(R.string.usage_mobile))
            expect(act.shows(a, c.getString(R.string.usage_bytes, bytes(2 * GIB), bytes(2 * GIB - GIB / 4), bytes(GIB / 4)))) {
                "нет счёта мобильной сети: ${act.texts(a)}"
            }
            expect(act.shows(a, c.getString(R.string.usage_bytes, bytes(GIB / 2), bytes(GIB / 2), bytes(0)))) { "нет счёта Wi-Fi: ${act.texts(a)}" }

            // Порог 1,5 ГБ — меньше уже насчитанного: на экране — предупреждением.
            act.tap(a, c.getString(R.string.usage_limit))
            act.type(a, c.getString(R.string.usage_limit_hint), "1,5")
            act.tap(a, c.getString(R.string.action_save))
            val of = c.getString(R.string.usage_limit_of, bytes(2 * GIB), bytes(GIB * 3 / 2))
            act.waitFor(a, of)
            expect(act.colorOf(a, of) == c.getColor(R.color.warning)) { "порог пройден — не предупреждением" }

            // Следующее приращение — уведомление, один раз за период.
            val alert = usage.record(UsageBytes(0, 1), NetworkType.MOBILE)
            expect(alert != null) { "порог пройден, а предупреждения нет" }
            expect(usage.record(UsageBytes(0, 1), NetworkType.MOBILE) == null) { "второе предупреждение в том же периоде" }
            act.d.main { UsageAlerts.show(c, act.graph(a).core, alert!!) }
            val shown = shadowOf(c.getSystemService(NotificationManager::class.java)).allNotifications
            expect(shown.any { it.extras.getString("android.title") == c.getString(R.string.usage_alert_title) }) { "уведомления о пороге нет" }

            // День начала периода — 15-е.
            act.tap(a, c.getString(R.string.usage_start_day))
            val picker = act.view(a, NumberPicker::class.java)
            expect(picker != null) { "нет выбора дня" }
            act.d.main { picker!!.value = 15 }
            act.tap(a, c.getString(R.string.action_save))
            act.waitFor(a, c.getString(R.string.usage_start_day_value, 15))
            expect(usage.settings().periodStartDay == 15) { "день начала не сохранён" }

            act.tap(a, c.getString(R.string.usage_reset))
            act.waitFor(a, c.getString(R.string.usage_reset_confirm))
            act.tap(a, c.getString(android.R.string.ok))
            act.waitFor(a, c.getString(R.string.usage_bytes, bytes(0), bytes(0), bytes(0)))
            expect(usage.summary().periodTotal.total == 0L) { "сброс не обнулил период" }
        }
    }

    private companion object {
        const val GIB = 1L shl 30
    }
}
