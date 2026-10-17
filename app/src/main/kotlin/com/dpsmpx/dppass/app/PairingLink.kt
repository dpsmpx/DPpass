package com.dpsmpx.dppass.app

import android.content.Context
import com.dpsmpx.dppass.connection.Pairing
import com.dpsmpx.dppass.core.Clock
import com.dpsmpx.dppass.engine.ShareSpec
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.isActive
import java.io.IOException
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.net.SocketTimeoutException

/**
 * Сокеты сопряжения (D-56). Раздающий телефон слушает порт сопряжения
 * только по нажатию, не дольше окна и только на адресах раздачи — никогда
 * на `0.0.0.0`, Wi-Fi-клиенте или мобильной сети, — и принимает одно
 * соединение: одна попытка на одно нажатие. Подключающийся телефон ищет
 * его там же, где устройство раздачи (D-55): на шлюзе своей сети.
 */
object PairingLink {
    private const val ACCEPT_STEP_MILLIS = 500
    private const val CONNECT_TIMEOUT_MILLIS = 1_500

    /**
     * Хозяин: ждать одно соединение на адресах [endpoints] в пределах окна.
     * null — окно вышло, ожидание отменили или порт занят. Блокирует поток.
     */
    suspend fun acceptOne(endpoints: List<ShareSpec.Endpoint>, windowMillis: Long = Pairing.WINDOW_MILLIS): Socket? {
        val servers = endpoints.mapNotNull { e ->
            try {
                ServerSocket().apply {
                    reuseAddress = true
                    // Адрес из байтов — без DNS: getByAddress имён не резолвит.
                    bind(InetSocketAddress(InetAddress.getByAddress(e.address.toBytes()), Pairing.PORT), 1)
                    soTimeout = ACCEPT_STEP_MILLIS
                }
            } catch (e: IOException) {
                null
            }
        }
        if (servers.isEmpty()) return null
        try {
            val deadline = Clock.MONOTONIC.nowMillis() + windowMillis
            while (currentCoroutineContext().isActive && Clock.MONOTONIC.nowMillis() < deadline) {
                for (s in servers) {
                    try {
                        return s.accept().apply { soTimeout = Pairing.WINDOW_MILLIS.toInt() }
                    } catch (e: SocketTimeoutException) {
                        // Шаг ожидания вышел — следующий адрес или следующий круг.
                    }
                }
            }
            return null
        } finally {
            servers.forEach { runCatching { it.close() } }
        }
    }

    /**
     * Гость: шлюз своей сети, на котором ждут сопряжения, — первое удачное
     * соединение сокетом этой сети. null — никто не ждёт.
     */
    fun connectToHost(context: Context): Socket? {
        for (g in RelayNetworks.gateways(context)) {
            val socket = g.network.socketFactory.createSocket()
            try {
                socket.connect(InetSocketAddress(InetAddress.getByAddress(g.address.toBytes()), Pairing.PORT), CONNECT_TIMEOUT_MILLIS)
                socket.soTimeout = Pairing.WINDOW_MILLIS.toInt()
                return socket
            } catch (e: IOException) {
                runCatching { socket.close() }
            }
        }
        return null
    }
}
