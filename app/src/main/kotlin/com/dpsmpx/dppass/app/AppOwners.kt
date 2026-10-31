package com.dpsmpx.dppass.app

import android.content.Context
import android.content.pm.PackageManager
import android.net.ConnectivityManager
import android.os.Build
import android.os.Process
import android.system.OsConstants
import com.dpsmpx.dppass.connection.ConnectionOwners
import com.dpsmpx.dppass.core.IpAddress
import com.dpsmpx.dppass.engine.ConnNetwork
import com.dpsmpx.dppass.engine.EngineConnection
import com.dpsmpx.dppass.engine.InboundKind
import java.net.InetAddress
import java.net.InetSocketAddress
import java.util.concurrent.ConcurrentHashMap

/**
 * Приложение у соединения (D-106): Android 10+ отвечает VPN-приложению,
 * чей сокет — по паре адресов из TUN (`getConnectionOwnerUid`). Владелец —
 * имя пакета: стабильно и годится для журнала уникальных; подпись — ярлык
 * ([label]). На Android 8–9 и для входов без TUN (локальный прокси,
 * раздача, свои запросы DPpass) — не узнать: null.
 */
class AppOwners(private val context: Context) : ConnectionOwners {
    private val labels = ConcurrentHashMap<String, String>()

    override fun owner(c: EngineConnection): String? {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.Q || c.inboundKind != InboundKind.TUN) return null
        val local = socket(c.source) ?: return null
        val remote = socket(c.target) ?: return null
        val protocol = if (c.network == ConnNetwork.TCP) OsConstants.IPPROTO_TCP else OsConstants.IPPROTO_UDP
        val uid = try {
            context.getSystemService(ConnectivityManager::class.java).getConnectionOwnerUid(protocol, local, remote)
        } catch (e: SecurityException) {
            // Не наш VPN сейчас (туннель только что закрылся) — не узнать.
            return null
        } catch (e: IllegalArgumentException) {
            return null
        }
        if (uid == Process.INVALID_UID) return null
        return context.packageManager.getPackagesForUid(uid)?.minOrNull() ?: "uid $uid"
    }

    /** Ярлык приложения по имени пакета; не найти — само имя. */
    fun label(owner: String): String = labels.getOrPut(owner) {
        try {
            val pm = context.packageManager
            val info = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                pm.getApplicationInfo(owner, PackageManager.ApplicationInfoFlags.of(0))
            } else {
                @Suppress("DEPRECATION") // замена — ApplicationInfoFlags, только с API 33
                pm.getApplicationInfo(owner, 0)
            }
            pm.getApplicationLabel(info).toString().ifBlank { owner }
        } catch (e: PackageManager.NameNotFoundException) {
            owner
        }
    }

    private companion object {
        /** «адрес:порт» из снимка ядра → адрес сокета без DNS (только IP; имя — null). */
        fun socket(text: String): InetSocketAddress? {
            val i = text.lastIndexOf(':')
            if (i <= 0) return null
            val port = text.substring(i + 1).toIntOrNull()?.takeIf { it in 1..65535 } ?: return null
            val ip = IpAddress.parse(text.substring(0, i).removePrefix("[").removeSuffix("]")) ?: return null
            // Адрес из байтов — без DNS: getByAddress имён не резолвит.
            return InetSocketAddress(InetAddress.getByAddress(ip.toBytes()), port)
        }
    }
}
