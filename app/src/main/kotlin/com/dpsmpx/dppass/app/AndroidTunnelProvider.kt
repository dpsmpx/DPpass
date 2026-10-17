package com.dpsmpx.dppass.app

import android.content.pm.PackageManager
import android.net.IpPrefix
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import com.dpsmpx.dppass.diagnostics.DiagCode
import com.dpsmpx.dppass.diagnostics.Diagnostic
import com.dpsmpx.dppass.diagnostics.Outcome
import com.dpsmpx.dppass.routing.AppPolicy
import com.dpsmpx.dppass.tunnel.TunnelHandle
import com.dpsmpx.dppass.tunnel.TunnelProvider
import com.dpsmpx.dppass.tunnel.TunnelSpec
import java.net.InetAddress

/**
 * TunnelSpec → `VpnService.Builder` один к одному (D-17). Решений здесь
 * нет: что маршрутизировать и кого исключить, уже решил `tunnel/`.
 */
class AndroidTunnelProvider(private val service: VpnService) : TunnelProvider {
    override suspend fun establish(spec: TunnelSpec): Outcome<TunnelHandle> {
        val b = service.Builder()
        try {
            b.setSession("DPpass")
            b.setMtu(spec.mtu)
            b.addAddress(spec.address4.network.toInet(), spec.address4.prefix)
            spec.address6?.let { b.addAddress(it.network.toInet(), it.prefix) }
            for (r in spec.routes) b.addRoute(r.network.toInet(), r.prefix)
            if (spec.excludedRoutes.isNotEmpty() && Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                for (r in spec.excludedRoutes) b.excludeRoute(IpPrefix(r.network.toInet(), r.prefix))
            }
            for (d in spec.dnsServers) b.addDnsServer(d.toInet())
            when (val apps = spec.apps) {
                AppPolicy.AllApps -> Unit
                is AppPolicy.ExceptApps -> for (p in apps.packages) b.addDisallowedApplication(p)
                is AppPolicy.OnlyApps -> for (p in apps.packages) b.addAllowedApplication(p)
            }
            b.setBlocking(false)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) b.setMetered(spec.metered)
        } catch (e: PackageManager.NameNotFoundException) {
            return Outcome.failure(Diagnostic.fromThrowable(DiagCode.TUN_ESTABLISH_FAILED, "приложение из политики не установлено", e))
        } catch (e: IllegalArgumentException) {
            return Outcome.failure(Diagnostic.fromThrowable(DiagCode.TUN_ESTABLISH_FAILED, "Builder отверг параметры TUN", e))
        }
        val pfd: ParcelFileDescriptor = b.establish()
            ?: return Outcome.failure(DiagCode.TUN_ESTABLISH_FAILED, "нет согласия пользователя на VPN (VpnService.prepare)")
        return Outcome.Success(object : TunnelHandle {
            override val fd: Int = pfd.fd
            override val spec: TunnelSpec = spec
            override fun protect(socketFd: Int): Boolean = service.protect(socketFd)
            override fun close() = pfd.close()
        })
    }

    // Адрес из байтов — без DNS: getByAddress не резолвит имён.
    private fun com.dpsmpx.dppass.core.IpAddress.toInet(): InetAddress = InetAddress.getByAddress(toBytes())
}
