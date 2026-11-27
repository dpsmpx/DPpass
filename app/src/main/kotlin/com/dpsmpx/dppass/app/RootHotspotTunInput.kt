package com.dpsmpx.dppass.app

import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.os.ParcelFileDescriptor
import com.dpsmpx.dppass.engine.SocketProtector
import com.dpsmpx.dppass.engine.TunInput
import java.io.IOException

/** D-120: дескриптор остаётся у владельца сессии до остановки ядра. */
internal object RootHotspotTunInput {
    fun isPhysical(physicalNetwork: Network, connectivity: ConnectivityManager): Boolean =
        connectivity.getNetworkCapabilities(physicalNetwork)?.let {
            it.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN) &&
                it.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET) &&
                it.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED)
        } == true

    fun create(tun: ParcelFileDescriptor, mtu: Int, physicalNetwork: Network, connectivity: ConnectivityManager): TunInput {
        fun isPhysical() = isPhysical(physicalNetwork, connectivity)
        check(isPhysical()) { "ROOT: физическая сеть недоступна" }
        require(mtu in 576..1500)
        return TunInput(tun.fd, mtu, SocketProtector { socketFd ->
            try {
                if (!isPhysical()) return@SocketProtector false
                // Дубликат не забирает fd у ядра; привязка действует на общий сокет.
                ParcelFileDescriptor.fromFd(socketFd).use { socket ->
                    physicalNetwork.bindSocket(socket.fileDescriptor)
                }
                true
            } catch (_: IOException) {
                false
            } catch (_: SecurityException) {
                false
            }
        })
    }
}
