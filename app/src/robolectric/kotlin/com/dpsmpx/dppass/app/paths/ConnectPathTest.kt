package com.dpsmpx.dppass.app.paths

import android.app.Activity
import com.dpsmpx.dppass.R
import com.dpsmpx.dppass.app.DPpassVpnService
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
 * Ключевой путь «подключение и отказ» (D-90): сервер есть → «Подключить» →
 * согласие на VPN → сервис туннеля → туннель не поднялся → экран говорит, что не
 * подключено и почему, а кнопка снова подключает. TUN на JVM нет:
 * Android здесь отвергает его так, как велит документ `establish()`, — дальше
 * всё настоящее: сервис, ядро Xray, состояние туннеля и экран.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [36], shadows = [SandboxVpnBuilder::class])
class ConnectPathTest {
    @Test
    fun failureShowsReasonAndConnectAgain() {
        Act().use { act ->
            val c = act.context
            // Android отвергает TUN (документ establish(): IllegalStateException) — отказ, а не «Подключение…» навсегда.
            SandboxVpnBuilder.answer = { throw IllegalStateException("синтетический отказ TUN") }
            val a = act.launch()
            act.seed(a, LINK)
            act.tap(a, c.getString(R.string.tab_connect))
            act.waitFor(a, c.getString(R.string.source_subscription, "Synthetic"))
            act.tap(a, c.getString(R.string.action_connect), PowerButton::class.java)

            // Android спрашивает согласие на VPN — пользователь соглашается; приложение запускает сервис туннеля.
            val consent = act.d.main { shadowOf(a).nextStartedActivityForResult }
            expect(consent != null) { "«Подключить» не спросило согласия на VPN" }
            act.d.main { shadowOf(a).receiveResult(consent!!.intent, Activity.RESULT_OK, null) }
            val app = RuntimeEnvironment.getApplication()
            val intent = act.d.main { shadowOf(app).nextStartedService }
            expect(intent?.component?.className == DPpassVpnService::class.java.name) { "согласие есть, а сервис туннеля не запущен: $intent" }
            val service = act.d.main { Robolectric.buildService(DPpassVpnService::class.java, intent).create().startCommand(0, 1) }

            act.d.waitUntil("туннель не поднялся — отказ с причиной", 15_000) { TunnelState.status.value is TunnelStatus.Failed }
            val reason = (TunnelState.status.value as TunnelStatus.Failed).reason
            expect(reason.code == DiagCode.TUN_ESTABLISH_FAILED) { "отказ — не TUN: $reason" }
            act.waitFor(a, c.getString(R.string.status_failed))
            expect(act.shows(a, reason.message)) { "причины отказа нет на экране: «${reason.message}»; видно: ${act.texts(a)}" }
            // Кнопка снова подключает, а не отключает: туннеля нет.
            val power = act.d.views(a).filterIsInstance<PowerButton>().single()
            expect(act.d.main { power.contentDescription } == c.getString(R.string.action_connect)) { "после отказа кнопка — не «Подключить»" }
            act.d.main { service.destroy() }
        }
    }

    private companion object {
        const val LINK = "vless://00000000-0000-4000-8000-000000000031@203.0.113.31:443?security=tls&sni=a.example.com#Alpha"
    }
}
