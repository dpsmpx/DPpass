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
        // Отказы Builder и establish() — ожидаемые (D-22): исключение мимо этого места
        // оставило бы «Подключение…» без причины (D-90: тест пути на JVM нашёл).
        val pfd: ParcelFileDescriptor = try {
            builder(spec).establish()
        } catch (e: PackageManager.NameNotFoundException) {
            return Outcome.failure(Diagnostic.fromThrowable(DiagCode.TUN_ESTABLISH_FAILED, "приложение из политики не установлено", e))
        } catch (e: IllegalArgumentException) {
            return Outcome.failure(Diagnostic.fromThrowable(DiagCode.TUN_ESTABLISH_FAILED, "Builder отверг параметры TUN", e))
        } catch (e: IllegalStateException) {
            // Параметр не применён системой, или согласие отозвано между prepare() и запуском.
            return Outcome.failure(Diagnostic.fromThrowable(DiagCode.TUN_ESTABLISH_FAILED, "Android не поднял TUN с этими параметрами", e))
        } catch (e: SecurityException) {
            return Outcome.failure(Diagnostic.fromThrowable(DiagCode.TUN_ESTABLISH_FAILED, "Android не разрешил приложению TUN", e))
        } ?: return Outcome.failure(DiagCode.TUN_ESTABLISH_FAILED, "нет согласия пользователя на VPN (VpnService.prepare)")
        return Outcome.Success(object : TunnelHandle {
            override val fd: Int = pfd.fd
            override val spec: TunnelSpec = spec
            override fun protect(socketFd: Int): Boolean = service.protect(socketFd)
            override fun close() = pfd.close()
        })
    }

    private fun builder(spec: TunnelSpec): VpnService.Builder {
        val b = service.Builder()
        b.setSession("DPpass")
        b.setMtu(spec.mtu)
        b.addAddress(spec.address4.address.toInet(), spec.address4.prefix)
        spec.address6?.let { b.addAddress(it.address.toInet(), it.prefix) }
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
        return b
    }

    // Адрес из байтов — без DNS: getByAddress не резолвит имён.
    private fun com.dpsmpx.dppass.core.IpAddress.toInet(): InetAddress = InetAddress.getByAddress(toBytes())
}
