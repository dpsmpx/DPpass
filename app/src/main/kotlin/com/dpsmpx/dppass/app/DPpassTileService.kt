package com.dpsmpx.dppass.app

import android.annotation.SuppressLint
import android.app.PendingIntent
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.service.quicksettings.Tile
import android.service.quicksettings.TileService
import com.dpsmpx.dppass.R
import com.dpsmpx.dppass.app.ui.MainThread
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * Плитка быстрых настроек (D-40): состояние туннеля и одно действие —
 * включить или выключить. Без согласия на VPN или без серверов —
 * открывает приложение: там видно, чего не хватает.
 *
 * Связывает её только система (`BIND_QUICK_SETTINGS_TILE`, T13); плитка
 * активная — система спрашивает её, только когда сервис просит
 * (`TileService.requestListeningState`).
 */
class DPpassTileService : TileService() {
    private var scope: CoroutineScope? = null
    private var watch: Job? = null

    override fun onStartListening() {
        super.onStartListening()
        val s = CoroutineScope(SupervisorJob() + MainThread)
        scope = s
        watch = s.launch { TunnelState.status.collect { render(it) } }
    }

    override fun onStopListening() {
        watch?.cancel()
        scope?.cancel()
        scope = null
        super.onStopListening()
    }

    private fun render(status: TunnelStatus) {
        val tile = qsTile ?: return
        tile.state = when {
            status is TunnelStatus.Connected -> Tile.STATE_ACTIVE
            status.busy -> Tile.STATE_ACTIVE
            else -> Tile.STATE_INACTIVE
        }
        tile.label = getString(R.string.app_name)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            tile.subtitle = getString(
                when (status) {
                    is TunnelStatus.Connected -> R.string.status_connected
                    is TunnelStatus.Connecting -> R.string.status_connecting
                    TunnelStatus.Stopping -> R.string.status_stopping
                    is TunnelStatus.Failed -> R.string.status_failed
                    TunnelStatus.Idle -> R.string.status_off
                },
            )
        }
        tile.updateTile()
    }

    override fun onClick() {
        super.onClick()
        if (isLocked) {
            unlockAndRun { onClick() }
            return
        }
        val status = TunnelState.status.value
        if (status.busy) {
            DPpassVpnService.stop(this)
            return
        }
        if (status == TunnelStatus.Stopping) return
        val s = scope ?: return
        s.launch {
            // Без согласия на VPN подключиться нельзя — его даёт только экран приложения;
            // без VPN (D-95) согласие не нужно.
            val withoutVpn = withContext(Dispatchers.IO) { AppGraph.core(this@DPpassTileService).localProxy.enabled() }
            if (!withoutVpn && VpnService.prepare(this@DPpassTileService) != null) {
                openApp()
                return@launch
            }
            val canConnect = withContext(Dispatchers.IO) {
                val core = AppGraph.core(this@DPpassTileService)
                if (core.activation.state.activeConfig == null) core.restore()
                val prefs = AppPrefs(this@DPpassTileService)
                // Устройство раздачи (D-55) — подключаться есть к чему и без подписки.
                val relay = prefs.selectedRelay?.let(core.relays::find) != null
                // Без сервера (D-73) — туннель для сайтов списка, когда серверов нет.
                core.activation.state.activeConfig?.profiles?.isNotEmpty() == true || relay ||
                    core.serverlessReady(prefs.splitSites(), prefs.serverless, relaySelected = relay)
            }
            if (canConnect) DPpassVpnService.start(this@DPpassTileService) else openApp()
        }
    }

    // До API 34 есть только startActivityAndCollapse(Intent); с API 34 — вариант с PendingIntent (выше).
    @SuppressLint("StartActivityAndCollapseDeprecated")
    private fun openApp() {
        val intent = Intent(this, MainActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            startActivityAndCollapse(PendingIntent.getActivity(this, 0, intent, PendingIntent.FLAG_IMMUTABLE))
        } else {
            @Suppress("DEPRECATION") // замена с PendingIntent — только с API 34
            startActivityAndCollapse(intent)
        }
    }
}
