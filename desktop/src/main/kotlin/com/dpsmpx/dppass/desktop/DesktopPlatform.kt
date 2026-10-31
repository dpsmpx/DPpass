package com.dpsmpx.dppass.desktop

import com.dpsmpx.dppass.connection.toTunInput
import com.dpsmpx.dppass.core.Cidr
import com.dpsmpx.dppass.diagnostics.Diagnostic
import com.dpsmpx.dppass.diagnostics.Outcome
import com.dpsmpx.dppass.engine.ShareSpec
import com.dpsmpx.dppass.engine.SystemTun
import com.dpsmpx.dppass.engine.TunInput
import com.dpsmpx.dppass.network.NetworkType
import com.dpsmpx.dppass.network.ProbeNetwork
import com.dpsmpx.dppass.tunnel.TunnelHandle
import com.dpsmpx.dppass.tunnel.TunnelSpec

/**
 * Сеть ПК (D-79): [key] — для памяти режима (D-64), [type] — для учёта
 * трафика (D-92). Ни то, ни другое в журнал не идёт.
 */
interface DesktopNetwork {
    val key: Long
    val type: NetworkType
}

/**
 * Чем ПК различаются (D-74, D-97) для сеанса и окна: можно ли поднять
 * туннель и почему нет, какая сейчас сеть, идёт ли проверка сети при
 * поднятом туннеле, чего на этой системе нет. Окно, сеанс и хранение —
 * общий код.
 */
interface DesktopHost {
    /** `linux` или `windows` — в журнал и сводку ядра. */
    val id: String

    fun tunnelAllowed(): Boolean

    /** Почему туннель не поднять — для окна; там же — выход «без VPN» (D-95). */
    val tunnelRefusal: String

    /** Сеть сейчас; null — маршрута по умолчанию нет. */
    fun network(): DesktopNetwork?

    /** Проверка сети при поднятом туннеле (D-79, D-80): пробы мимо него. */
    val checksUnderTunnel: Boolean

    /** Чего на этой системе нет и почему — для окна (D-97); null — есть всё. */
    val absent: String?

    /** Уведомления рабочего стола (D-92). */
    val notifier: DesktopNotifier

    /** Тёмная ли тема системы; null — система не говорит, решает окно по своим признакам. */
    fun systemDark(): Boolean?
}

/** Сокеты проб проверки сети (D-79) — мимо туннеля; [ready] — причина, по которой сейчас нельзя. */
interface DesktopProbeNetwork : ProbeNetwork {
    fun ready(): Diagnostic?
}

/**
 * Поднятый туннель оболочки: TUN платформы с fd ([tunInput], Linux, D-74)
 * или TUN, который создаёт само ядро ([systemTun], Windows, D-97). Одно из
 * двух.
 */
interface DesktopTunnel {
    val tunInput: TunInput?
    val systemTun: SystemTun?

    fun close()
}

/**
 * Точка доступа ПК для раздачи (D-84 — Linux, D-101 — Windows): где ПК сам
 * раздаёт сеть, по словам системы. Сомнение — адресов нет: лучше не
 * раздавать, чем открыть вход прокси не в той сети.
 */
interface DesktopShares {
    fun find(): ShareScan

    /** Подпись под переключателем раздачи: когда она действует на этой системе. */
    val condition: String

    /** Строка «Важно знать» о межсетевом экране ПК. */
    val firewall: String
}

/**
 * Адреса раздачи сейчас; [absent] — почему их нет, для окна (пусто, когда
 * адреса есть); [seen] — что видно, для журнала: без имён и адресов (D-57).
 */
data class ShareScan(val endpoints: List<ShareSpec.Endpoint>, val absent: String, val seen: String)

/**
 * Поднять туннель по [TunnelSpec]; [share] — подсети раздачи мимо туннеля
 * (D-84, D-101); [via] — интерфейс сети устройства раздачи (D-102): на
 * Windows к нему привязываются сокеты ядра, на Linux путь к нему и так
 * знает таблица `main`.
 */
fun interface DesktopTunnels {
    fun establish(spec: TunnelSpec, share: List<Cidr>, via: String?): Outcome<DesktopTunnel>
}

/** Linux (D-74): `CAP_NET_ADMIN` у процесса, сеть — из `/proc/net/route`, смена сети — наблюдается. */
class LinuxHost(private val platform: LinuxPlatform) : DesktopHost {
    override val id: String = "linux"

    override fun tunnelAllowed(): Boolean = platform.hasNetAdmin()

    override val tunnelRefusal: String =
        "DPpass запущен без права CAP_NET_ADMIN — туннель (VPN) не поднять. Запустите его ярлыком DPpass " +
            "или командой dppass: пароль администратора нужен для запуска с одной этой возможностью (D-74). " +
            "Или подключитесь без VPN: прокси для программ, где его можно указать (D-95)."

    override fun network(): DesktopNetwork? = LinuxNetwork.current()

    override val checksUnderTunnel: Boolean = true

    override val absent: String? = null

    override val notifier: DesktopNotifier = DesktopNotify()

    /** Тему Linux окно узнаёт само: `GTK_THEME`, `kdeglobals` ([com.dpsmpx.dppass.desktop.ui.Theme]). */
    override fun systemDark(): Boolean? = null
}

/** Туннель Linux — TUN с fd и правилами `ip` ([LinuxTunnelProvider]). */
class LinuxTunnels(private val provider: LinuxTunnelProvider) : DesktopTunnels {
    override fun establish(spec: TunnelSpec, share: List<Cidr>, via: String?): Outcome<DesktopTunnel> = when (val t = provider.establish(spec, share)) {
        is Outcome.Failure -> t
        is Outcome.Success -> Outcome.Success(Fd(t.value), t.diagnostics)
    }

    private class Fd(private val handle: TunnelHandle) : DesktopTunnel {
        override val tunInput: TunInput = handle.toTunInput()
        override val systemTun: SystemTun? = null

        override fun close() = handle.close()
    }
}
