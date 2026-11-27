package com.dpsmpx.dppass.app

import android.net.wifi.WifiManager
import android.os.Handler

/** D-120: резервируем локальную AP без запроса системной интернет-раздачи. */
internal object RootHotspotLocalAccessPoint {
    fun reservation() = RootHotspotReservation<WifiManager.LocalOnlyHotspotReservation> { it.close() }

    /**
     * Вызывать после согласия пользователя и выдачи разрешений Wi-Fi.
     * pending владеет reservation до take; после take вызывающий обязан закрыть её.
     * onStarted не подтверждает интерфейс, изоляцию или готовность маршрута.
     * onStopped является уведомлением, а не доказательством исчезновения AP.
     */
    fun request(
        wifi: WifiManager,
        handler: Handler,
        pending: RootHotspotReservation<WifiManager.LocalOnlyHotspotReservation>,
        onStopped: () -> Unit,
    ) {
        try {
            wifi.startLocalOnlyHotspot(object : WifiManager.LocalOnlyHotspotCallback() {
                override fun onStarted(reservation: WifiManager.LocalOnlyHotspotReservation) =
                    pending.started(reservation)

                override fun onStopped() {
                    try {
                        pending.failed(IllegalStateException("Точка доступа остановилась"))
                    } finally {
                        onStopped.invoke()
                    }
                }

                override fun onFailed(reason: Int) =
                    pending.failed(IllegalStateException("Отказ Android: $reason"))
            }, handler)
        } catch (failure: Throwable) {
            try {
                pending.failed(failure)
            } catch (cleanup: Throwable) {
                if (cleanup !== failure) failure.addSuppressed(cleanup)
            }
            throw failure
        }
    }
}
