package com.dpsmpx.dppass.app.paths

import android.app.Activity
import android.os.ParcelFileDescriptor
import com.dpsmpx.dppass.R
import com.dpsmpx.dppass.app.DPpassVpnService
import com.dpsmpx.dppass.app.DeviceLog
import com.dpsmpx.dppass.app.TunnelState
import com.dpsmpx.dppass.app.TunnelStatus
import com.dpsmpx.dppass.app.device.expect
import com.dpsmpx.dppass.app.ui.PowerButton
import com.dpsmpx.dppass.diagnostics.Diagnostic
import org.robolectric.Robolectric
import org.robolectric.RuntimeEnvironment
import org.robolectric.Shadows.shadowOf

/**
 * Путь подключения до отказа (D-90): сервер из [link] → «Подключить» →
 * согласие → сервис туннеля; TUN отвечает [tun]. Дождаться
 * отказа, проверить экран (причина видна, кнопка снова подключает) и
 * вернуть причину.
 */
internal fun connectUntilFailed(link: String, tun: () -> ParcelFileDescriptor?): Diagnostic {
    SandboxVpnBuilder.answer = tun
    Act().use { act ->
        val c = act.context
        val a = act.launch()
        act.seed(a, link)
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

        try {
            act.d.waitUntil("туннель не поднялся — отказ с причиной", 15_000) { TunnelState.status.value is TunnelStatus.Failed }
        } catch (e: AssertionError) {
            val tail = DeviceLog.memory.snapshot().takeLast(12).joinToString(" | ") { "${it.event} ${it.fields}" }
            throw AssertionError("${e.message}; состояние туннеля: ${TunnelState.status.value}; журнал: $tail", e)
        }
        val reason = (TunnelState.status.value as TunnelStatus.Failed).reason
        act.waitFor(a, c.getString(R.string.status_failed))
        expect(act.shows(a, reason.message)) { "причины отказа нет на экране: «${reason.message}»; видно: ${act.texts(a)}" }
        // Кнопка снова подключает, а не отключает: туннеля нет.
        val power = act.d.views(a).filterIsInstance<PowerButton>().single()
        expect(act.d.main { power.contentDescription } == c.getString(R.string.action_connect)) { "после отказа кнопка — не «Подключить»" }
        act.d.main { service.destroy() }
        return reason
    }
}
