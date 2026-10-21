package com.dpsmpx.dppass.desktop

import com.dpsmpx.dppass.core.Cidr
import com.dpsmpx.dppass.diagnostics.DiagCode
import com.dpsmpx.dppass.diagnostics.Diagnostic
import com.dpsmpx.dppass.engine.xray.XrayBackend
import com.dpsmpx.dppass.routing.AppPolicy
import com.dpsmpx.dppass.tunnel.TunnelSpec

/**
 * Команда `ip` (iproute2) — аргументы списком, без shell (T17).
 * [cleanup] — уборка: того, что убирается, может и не быть, отказ не
 * ошибка. [untilFails] — повторять, пока выполняется: правило с тем же
 * приоритетом могло остаться не одно.
 */
data class IpCommand(val args: List<String>, val cleanup: Boolean = false, val untilFails: Boolean = false) {
    override fun toString(): String = "ip " + args.joinToString(" ")
}

/**
 * Что на Linux делает `VpnService.Builder` (D-74): адреса, MTU, маршруты и
 * правила по [TunnelSpec] — один к одному, ничего не решая самому (D-17).
 *
 * - Таблица [TABLE]: маршруты спецификации через [DEVICE]; исключённые
 *   (`bypassLan`) — `throw`: поиск идёт дальше, к `main`.
 * - Таблица [DNS_TABLE]: только «всё через [DEVICE]» — запрос DNS на порт 53
 *   любого адреса, в том числе резолвера роутера, уходит в туннель, а ядро
 *   перехватывает его (`XrayCompiler(dnsHijackAnyAddress = true)`).
 * - Правила по приоритету: сокеты ядра с меткой [MARK] → `main` (мимо
 *   туннеля, T4); DNS → [DNS_TABLE]; остальное → [TABLE].
 */
object LinuxRoutes {
    const val DEVICE: String = XrayBackend.TUN_NAME
    const val TABLE: Int = 7350
    const val DNS_TABLE: Int = 7351

    /** Метка сокетов ядра и резолвера моста; договор с мостом — только значение, передаётся из Kotlin. */
    const val MARK: Int = 0x7350

    const val PRIORITY_MARK: Int = 7350
    const val PRIORITY_DNS_UDP: Int = 7351
    const val PRIORITY_DNS_TCP: Int = 7352
    const val PRIORITY_TUNNEL: Int = 7353

    private val PRIORITIES = listOf(PRIORITY_MARK, PRIORITY_DNS_UDP, PRIORITY_DNS_TCP, PRIORITY_TUNNEL)

    /**
     * Политика приложений на Linux не выразима: программы не различаются.
     * «Все, кроме DPpass» выполняется меткой сокетов ядра; иной выбор —
     * отказ, а не туннель для всех (D-05).
     */
    fun appPolicyProblem(spec: TunnelSpec, selfPackage: String): Diagnostic? {
        val apps = spec.apps
        if (apps is AppPolicy.ExceptApps && apps.packages == setOf(selfPackage)) return null
        return Diagnostic.error(
            DiagCode.APP_POLICY_CONFLICT,
            "на Linux программы не различаются: выбор приложений туннеля (${describe(apps)}) здесь не выполнить — " +
                "уберите его, туннель пойдёт для всех программ",
            "$.routing.apps",
        )
    }

    private fun describe(apps: AppPolicy): String = when (apps) {
        AppPolicy.AllApps -> "все"
        is AppPolicy.ExceptApps -> "все, кроме ${apps.packages.size}"
        is AppPolicy.OnlyApps -> "только ${apps.packages.size}"
    }

    /** Поднять: адреса и MTU, затем маршруты, затем правила — пока правил нет, туннелю ничего не уходит. */
    fun up(spec: TunnelSpec, ipv6: Boolean): List<IpCommand> {
        val out = mutableListOf<IpCommand>()
        out += ip("link", "set", "dev", DEVICE, "mtu", spec.mtu.toString())
        out += ip("-4", "addr", "add", spec.address4.toString(), "dev", DEVICE)
        if (ipv6) spec.address6?.let { out += ip("-6", "addr", "add", it.toString(), "dev", DEVICE, "nodad") }
        out += ip("link", "set", "dev", DEVICE, "up")
        for (v4 in families(ipv6)) {
            val f = if (v4) "-4" else "-6"
            for (r in spec.routes.filter { it.isV4 == v4 }) out += ip(f, "route", "add", r.toString(), "dev", DEVICE, "table", "$TABLE")
            for (r in spec.excludedRoutes.filter { it.isV4 == v4 }) out += ip(f, "route", "add", "throw", r.toString(), "table", "$TABLE")
            out += ip(f, "route", "add", (if (v4) Cidr.ALL_V4 else Cidr.ALL_V6).toString(), "dev", DEVICE, "table", "$DNS_TABLE")
            out += ip(f, "rule", "add", "fwmark", "0x" + MARK.toString(16), "lookup", "main", "priority", "$PRIORITY_MARK")
            out += ip(f, "rule", "add", "ipproto", "udp", "dport", "53", "lookup", "$DNS_TABLE", "priority", "$PRIORITY_DNS_UDP")
            out += ip(f, "rule", "add", "ipproto", "tcp", "dport", "53", "lookup", "$DNS_TABLE", "priority", "$PRIORITY_DNS_TCP")
            out += ip(f, "rule", "add", "lookup", "$TABLE", "priority", "$PRIORITY_TUNNEL")
        }
        return out
    }

    /**
     * Убрать своё — правила раньше таблиц. Для IPv4 и IPv6 всегда: прежний
     * запуск мог поднять IPv6, которого теперь нет. Устройство исчезает само
     * с последним fd.
     */
    fun down(): List<IpCommand> = families(ipv6 = true).flatMap { v4 ->
        val f = if (v4) "-4" else "-6"
        PRIORITIES.map { IpCommand(listOf(f, "rule", "del", "priority", "$it"), cleanup = true, untilFails = true) } +
            listOf(TABLE, DNS_TABLE).map { IpCommand(listOf(f, "route", "flush", "table", "$it"), cleanup = true) }
    }

    private fun families(ipv6: Boolean): List<Boolean> = if (ipv6) listOf(true, false) else listOf(true)

    private fun ip(vararg args: String) = IpCommand(args.toList())
}
