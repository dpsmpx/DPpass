package com.dpsmpx.dppass.app

import android.net.wifi.WifiManager
import android.os.Handler

/** D-120: резервируем локальную AP без запроса системной интернет-раздачи. */
internal object RootHotspotLocalAccessPoint {
    /** Вызывать после согласия пользователя и выдачи разрешений Wi-Fi.
     * Получатель владеет reservation и обязан закрыть её, в том числе при отмене запуска.
     * onStarted не подтверждает интерфейс, изоляцию или готовность маршрута.
     */
    fun request(
        wifi: WifiManager,
        handler: Handler,
        onStarted: (WifiManager.LocalOnlyHotspotReservation) -> Unit,
        onStopped: () -> Unit,
        onFailed: (Int) -> Unit,
    ) {
        wifi.startLocalOnlyHotspot(object : WifiManager.LocalOnlyHotspotCallback() {
            override fun onStarted(reservation: WifiManager.LocalOnlyHotspotReservation) {
                try {
                    onStarted.invoke(reservation)
                } catch (failure: Exception) {
                    runCatching { reservation.close() }.exceptionOrNull()?.let(failure::addSuppressed)
                    throw failure
                }
            }

            override fun onStopped() = onStopped.invoke()

            override fun onFailed(reason: Int) = onFailed.invoke(reason)
        }, handler)
    }
}
