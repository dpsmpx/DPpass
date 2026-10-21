package com.dpsmpx.dppass.desktop

import com.dpsmpx.dppass.config.ConfigLoader
import com.dpsmpx.dppass.core.Cidr
import com.dpsmpx.dppass.core.Clock
import com.dpsmpx.dppass.core.Json
import com.dpsmpx.dppass.core.JsonValue
import com.dpsmpx.dppass.diagnostics.Logger
import com.dpsmpx.dppass.diagnostics.MemoryLogSink
import com.dpsmpx.dppass.diagnostics.Outcome
import com.dpsmpx.dppass.engine.CompilePlan
import com.dpsmpx.dppass.engine.SocketProtector
import com.dpsmpx.dppass.engine.TunInput
import com.dpsmpx.dppass.engine.xray.JniXrayRuntime
import com.dpsmpx.dppass.engine.xray.XrayCompiler
import com.dpsmpx.dppass.engine.xray.XrayProxyEngine
import com.dpsmpx.dppass.routing.AppPolicy
import com.dpsmpx.dppass.tunnel.Ipv6Mode
import com.dpsmpx.dppass.tunnel.TunnelHandle
import com.dpsmpx.dppass.tunnel.TunnelSpec
import com.dpsmpx.dppass.tunnel.TunnelSpecBuilder
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.withContext
import java.io.File
import java.io.IOException
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.util.concurrent.atomic.AtomicInteger

/**
 * Проверка туннеля Linux на настоящем ядре (`tools/desktop/netns_check.py`,
 * D-74): тот же [LinuxTunnelProvider] с мостом пакета поднимает TUN, ядро
 * Linux отвечает `ip route get`, куда пошёл бы пакет (обычный, с меткой ядра,
 * в локальную сеть, DNS к роутеру). Затем ядро Xray запускается на этом TUN
 * дважды (оркестратор так перебирает кандидатов, D-15: ядру — копия fd, D-74),
 * соединение уходит в туннель, и ядро звонит серверу — сокет проходит
 * защитника (метка). Туннель закрывается. Отчёт — JSON в файл [out]; что из
 * него следует — решает скрипт. Запускать — только в своём сетевом
 * пространстве имён: правила меняют маршрутизацию системы.
 */
object SelfCheck {
    /** Пробы `ip route get`: имя → аргументы. Адреса — документационные (RFC 5737, 3849) и сеть проверки. */
    val PROBES: Map<String, List<String>> = linkedMapOf(
        "internet" to listOf("-4", "route", "get", "192.0.2.10"),
        "internet_marked" to listOf("-4", "route", "get", "192.0.2.10", "mark", "0x" + LinuxRoutes.MARK.toString(16)),
        "lan" to listOf("-4", "route", "get", "192.168.77.1"),
        "lan_dns_udp" to listOf("-4", "route", "get", "192.168.77.1", "ipproto", "udp", "dport", "53"),
        "lan_dns_tcp" to listOf("-4", "route", "get", "192.168.77.1", "ipproto", "tcp", "dport", "53"),
        "lan_dns_marked" to listOf("-4", "route", "get", "192.168.77.1", "ipproto", "udp", "dport", "53", "mark", "0x" + LinuxRoutes.MARK.toString(16)),
        "internet6" to listOf("-6", "route", "get", "2001:db8::10"),
        "internet6_marked" to listOf("-6", "route", "get", "2001:db8::10", "mark", "0x" + LinuxRoutes.MARK.toString(16)),
    )

    /** Спецификация, как у конфигурации с «локальная сеть напрямую»: все маршруты, LAN исключён. */
    fun spec(): TunnelSpec = TunnelSpec(
        address4 = TunnelSpecBuilder.ADDRESS4,
        address6 = TunnelSpecBuilder.ADDRESS6,
        routes = listOf(Cidr.ALL_V4, Cidr.ALL_V6),
        excludedRoutes = TunnelSpecBuilder.LAN,
        dnsServers = listOf(TunnelSpecBuilder.TUN_DNS4),
        mtu = TunnelSpecBuilder.DEFAULT_MTU,
        apps = AppPolicy.ExceptApps(setOf(DesktopGraph.SELF)),
        ipv6Mode = Ipv6Mode.TUNNELED,
    )

    /**
     * Синтетический документ (как корпус `tests/data/configs/valid-minimal.json`):
     * сервер — адрес TEST-NET-1 без имени, ему отвечать некому — проверяется
     * только путь до сокета ядра.
     */
    private val DOC = """
        {"format": "dppass.config", "format_version": 1, "name": "self-check",
         "profiles": [{"id": "reality-1", "name": "Reality 1", "server": "192.0.2.1", "port": 443,
           "protocol": {"type": "vless", "id": "00000000-0000-4000-8000-000000000001", "flow": "vision"},
           "transport": {"type": "tcp"},
           "security": {"type": "reality", "server_name": "www.example.com",
             "public_key": "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8", "short_id": "01234567", "fingerprint": "chrome"}}],
         "routing": {"default": "proxy", "bypass_lan": true, "apps": {"mode": "all"}, "rules": []},
         "dns": {"servers": [{"id": "remote", "type": "udp", "address": "192.0.2.53", "route": "tunnel"}], "default": "remote"}}
    """.trimIndent()

    private suspend fun engine(paths: DesktopPaths, tun: TunnelHandle): JsonValue {
        val r = linkedMapOf<String, JsonValue?>()
        val runtime = JniXrayRuntime.load({ DesktopGraph.loadLibrary(paths) }, File(paths.install, "geodata").path)
        val engine = XrayProxyEngine(runtime)
        val ir = when (val l = ConfigLoader().load(DOC)) {
            is Outcome.Failure -> return Json.obj("error" to Json.str(l.errors.joinToString { it.render() }))
            is Outcome.Success -> l.value.ir
        }
        val compiled = when (val c = XrayCompiler(dnsHijackAnyAddress = true).compile(ir, CompilePlan(ir.profiles[0].id, withTun = true))) {
            is Outcome.Failure -> return Json.obj("error" to Json.str(c.errors.joinToString { it.render() }))
            is Outcome.Success -> c.value
        }
        val protectedSockets = AtomicInteger()
        val input = TunInput(
            tun.fd,
            tun.spec.mtu,
            SocketProtector { fd ->
                protectedSockets.incrementAndGet()
                tun.protect(fd)
            },
        )
        fun outcome(o: Outcome<*>): JsonValue? = Json.str(if (o is Outcome.Failure) o.errors.flatMap { it.renderWithCauses() }.joinToString("\n") else "ok")
        val first = engine.start(compiled, input)
        r["start1"] = outcome(first)
        first.valueOrNull()?.stop()
        val second = engine.start(compiled, input)
        r["start2"] = outcome(second)
        val session = second.valueOrNull()
        if (session != null) {
            // Соединение — в туннель (сокет JVM без метки): его примет стек TUN ядра,
            // а ядро позвонит серверу профиля — через защитника.
            withContext(Dispatchers.IO) {
                try {
                    Socket().use { it.connect(InetSocketAddress(InetAddress.getByAddress(PROBE_TARGET), PROBE_PORT), CONNECT_MILLIS) }
                } catch (_: IOException) {
                    // Ответа и не ждём: важен звонок ядра к серверу.
                }
            }
            for (i in 0 until WAIT_STEPS) {
                if (protectedSockets.get() > 0) break
                delay(WAIT_STEP_MILLIS)
            }
            r["traffic"] = session.stats().let { Json.obj("up" to Json.num(it.uplinkBytes), "down" to Json.num(it.downlinkBytes)) }
            session.stop()
        }
        r["protected_sockets"] = Json.num(protectedSockets.get().toLong())
        return Json.obj(*r.toList().toTypedArray())
    }

    private val PROBE_TARGET = byteArrayOf(192.toByte(), 0, 2, 10)
    private const val PROBE_PORT = 80
    private const val CONNECT_MILLIS = 2000
    private const val WAIT_STEPS = 50
    private const val WAIT_STEP_MILLIS = 100L

    suspend fun run(install: File, out: File): Boolean {
        DesktopGraph.loadLibrary(DesktopPaths(install, install))
        val platform = SystemLinuxPlatform()
        val sink = MemoryLogSink()
        val provider = LinuxTunnelProvider(platform, DesktopGraph.SELF, Logger("selfcheck", sink, Clock.SYSTEM::nowMillis))
        fun ip(args: List<String>): JsonValue = platform.ip(args).let { Json.obj("code" to Json.num(it.code.toLong()), "output" to Json.str(it.output.trim())) }
        val report = linkedMapOf<String, JsonValue?>("net_admin" to Json.bool(platform.hasNetAdmin()), "ipv6" to Json.bool(platform.ipv6Enabled()))
        val ok = when (val t = provider.establish(spec())) {
            is Outcome.Failure -> {
                report["establish"] = Json.str(t.errors.flatMap { it.renderWithCauses() }.joinToString("\n"))
                false
            }
            is Outcome.Success -> {
                report["establish"] = Json.str("ok")
                report["link"] = ip(listOf("addr", "show", "dev", LinuxRoutes.DEVICE))
                report["rules4"] = ip(listOf("-4", "rule", "show"))
                report["rules6"] = ip(listOf("-6", "rule", "show"))
                report["probes"] = Json.obj(*PROBES.map { (name, args) -> name to ip(args) }.toTypedArray())
                // Метка — тем же вызовом моста, что у сокетов ядра: на fd не сокета — отказ (ENOTSOCK).
                report["mark_tun_fd"] = Json.num(platform.markSocket(t.value.fd, LinuxRoutes.MARK).toLong())
                report["engine"] = engine(DesktopPaths(install, install), t.value)
                t.value.close()
                report["rules4_after"] = ip(listOf("-4", "rule", "show"))
                report["rules6_after"] = ip(listOf("-6", "rule", "show"))
                report["link_after"] = ip(listOf("link", "show", "dev", LinuxRoutes.DEVICE))
                true
            }
        }
        report["log"] = Json.strings(sink.snapshot().map { it.render() })
        out.writeText(Json.write(Json.obj(*report.toList().toTypedArray())) + "\n")
        return ok
    }
}
