package com.dpsmpx.dppass.app.paths

import android.app.Activity
import com.dpsmpx.dppass.R
import com.dpsmpx.dppass.app.DPpassVpnService
import com.dpsmpx.dppass.app.DeviceLog
import com.dpsmpx.dppass.app.TunnelState
import com.dpsmpx.dppass.app.TunnelStatus
import com.dpsmpx.dppass.app.device.expect
import com.dpsmpx.dppass.app.ui.PowerButton
import com.dpsmpx.dppass.diagnostics.DiagCode
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.Robolectric
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.Shadows.shadowOf
import org.robolectric.annotation.Config

/**
 * Ключевой путь «без VPN» (D-95): согласия на VPN нет → в окне отказа
 * «Подключиться без VPN» → режим включён по нажатию → сервис идёт без
 * согласия и без TUN, ядро Xray — с локальным прокси → экран прокси
 * показывает адрес, порт, логин и пароль и выключает режим. Сервер
 * синтетический (TEST-NET): подключение не проходит проверку здоровья, и
 * это отказ сервера, а не TUN.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [36])
class LocalProxyPathTest {
    @Test
    fun refusedVpnOffersProxyAndConnectsWithoutConsent() {
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

            // Окно отказа предлагает подключиться без VPN — до нажатия режим выключен.
            act.waitFor(a, c.getString(R.string.local_proxy_offer))
            val core = act.graph(a).core
            expect(!core.localProxy.enabled()) { "режим без VPN включён без нажатия" }
            // Что «Подключить» уже открыло (запрос разрешения на уведомления), — до нажатия: дальше смотрим только на новое.
            act.d.main {
                var pending = shadowOf(a).nextStartedActivityForResult
                while (pending != null) pending = shadowOf(a).nextStartedActivityForResult
            }
            act.tap(a, c.getString(R.string.local_proxy_offer))
            act.d.waitUntil("режим без VPN включён") { core.localProxy.enabled() }
            val app = RuntimeEnvironment.getApplication()
            val intent = act.d.main { shadowOf(app).nextStartedService }
            expect(intent?.component?.className == DPpassVpnService::class.java.name) { "сервис не запущен: $intent" }
            val asked = act.d.main { shadowOf(a).nextStartedActivityForResult }
            expect(asked == null) { "без VPN снова спросили согласие на VPN: ${asked?.intent} код ${asked?.requestCode}" }

            val service = act.d.main { Robolectric.buildService(DPpassVpnService::class.java, intent).create().startCommand(0, 1) }
            val port = core.localProxy.current().valueOrNull()!!.port
            act.d.waitUntil("ядро запущено с локальным прокси", 15_000) {
                DeviceLog.memory.snapshot().any { it.event == "local_proxy_up" && it.fields["port"] == port.toString() }
            }
            act.d.waitUntil("попытка закончилась", 60_000) { TunnelState.status.value is TunnelStatus.Failed }
            val reason = (TunnelState.status.value as TunnelStatus.Failed).reason
            expect(reason.code != DiagCode.TUN_ESTABLISH_FAILED) { "без VPN отказ — TUN: $reason" }
            expect(DeviceLog.memory.snapshot().none { it.event == "tunnel_up" }) { "без VPN поднят TUN" }
            act.d.main { service.destroy() }

            // Экран прокси: адрес, порт, логин и пароль; выключение — снова через VPN.
            act.waitFor(a, c.getString(R.string.local_proxy_row_on, port))
            act.tap(a, c.getString(R.string.local_proxy_title))
            act.waitFor(a, c.getString(R.string.local_proxy_credentials))
            val s = core.localProxy.current().valueOrNull()!!
            expect(act.shows(a, "127.0.0.1") && act.shows(a, port.toString())) { "нет адреса и порта: ${act.texts(a)}" }
            expect(act.shows(a, s.user.reveal()) && act.shows(a, s.password.reveal())) { "нет логина и пароля на экране прокси" }
            act.tap(a, c.getString(R.string.local_proxy_switch))
            act.d.waitUntil("режим без VPN выключен") { !core.localProxy.enabled() }
        }
    }

    private companion object {
        const val LINK = "vless://00000000-0000-4000-8000-000000000031@203.0.113.31:443?security=tls&sni=a.example.com#Alpha"
    }
}
