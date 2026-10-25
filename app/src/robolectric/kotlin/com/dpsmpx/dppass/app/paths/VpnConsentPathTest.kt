package com.dpsmpx.dppass.app.paths

import android.app.Activity
import com.dpsmpx.dppass.R
import com.dpsmpx.dppass.app.TunnelState
import com.dpsmpx.dppass.app.TunnelStatus
import com.dpsmpx.dppass.app.device.expect
import com.dpsmpx.dppass.app.ui.PowerButton
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.Shadows.shadowOf
import org.robolectric.annotation.Config

/**
 * Ключевой путь «подключение и отказ» — без согласия (D-90): «Подключить» →
 * Android спрашивает согласие на VPN → отказ (пользователь отказал, или
 * Android закрыл запрос сам из-за «Постоянного VPN» другого приложения) →
 * окно с причиной и выходом, сервис туннеля не запущен.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [36])
class VpnConsentPathTest {
    @Test
    fun refusedConsentExplainsAndDoesNotStartTunnel() {
        Act().use { act ->
            val c = act.context
            val a = act.launch()
            act.seed(a, LINK)
            act.tap(a, c.getString(R.string.tab_connect))
            act.waitFor(a, c.getString(R.string.source_subscription, "Synthetic"))
            act.tap(a, c.getString(R.string.action_connect), PowerButton::class.java)

            val consent = act.d.main { shadowOf(a).nextStartedActivityForResult }
            expect(consent != null) { "«Подключить» не спросило согласия на VPN" }
            act.d.main { shadowOf(a).receiveResult(consent!!.intent, Activity.RESULT_CANCELED, null) }

            act.waitFor(a, c.getString(R.string.status_failed))
            expect(act.shows(a, "«Постоянный VPN»")) { "в окне отказа нет выхода — «Постоянный VPN» другого приложения: ${act.texts(a)}" }
            val app = RuntimeEnvironment.getApplication()
            expect(act.d.main { shadowOf(app).nextStartedService } == null) { "без согласия запущен сервис туннеля" }
            expect(TunnelState.status.value == TunnelStatus.Idle) { "без согласия туннель — ${TunnelState.status.value}" }
        }
    }

    private companion object {
        const val LINK = "vless://00000000-0000-4000-8000-000000000031@203.0.113.31:443?security=tls&sni=a.example.com#Alpha"
    }
}
