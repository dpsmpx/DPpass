package com.dpsmpx.dppass.desktop

import com.dpsmpx.dppass.core.Cidr
import com.dpsmpx.dppass.diagnostics.DiagCode
import com.dpsmpx.dppass.diagnostics.Logger
import com.dpsmpx.dppass.diagnostics.MemoryLogSink
import com.dpsmpx.dppass.diagnostics.Outcome
import com.dpsmpx.dppass.routing.AppPolicy
import com.dpsmpx.dppass.tunnel.Ipv6Mode
import com.dpsmpx.dppass.tunnel.TunnelSpec
import com.dpsmpx.dppass.tunnel.TunnelSpecBuilder
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertTrue

private const val SELF = "com.dpsmpx.dppass"

private fun spec(bypassLan: Boolean = true, apps: AppPolicy = AppPolicy.ExceptApps(setOf(SELF))) = TunnelSpec(
    address4 = TunnelSpecBuilder.ADDRESS4,
    address6 = TunnelSpecBuilder.ADDRESS6,
    routes = listOf(Cidr.ALL_V4, Cidr.ALL_V6),
    excludedRoutes = if (bypassLan) TunnelSpecBuilder.LAN else emptyList(),
    dnsServers = listOf(TunnelSpecBuilder.TUN_DNS4),
    mtu = 1500,
    apps = apps,
    ipv6Mode = Ipv6Mode.TUNNELED,
)

private fun text(commands: List<IpCommand>) = commands.map { it.args.joinToString(" ") }

/** Подделка системы: что вызвано, по порядку; какая команда откажет. */
private class FakePlatform(
    var netAdmin: Boolean = true,
    var ipv6: Boolean = true,
    var tunFd: Int = 42,
    val failOn: (List<String>) -> Boolean = { false },
) : LinuxPlatform {
    val calls = mutableListOf<String>()

    override fun hasNetAdmin() = netAdmin

    override fun ipv6Enabled() = ipv6

    override fun openTun(name: String): Int = tunFd.also { calls += "open $name" }

    override fun closeFd(fd: Int): Int = 0.also { calls += "close $fd" }

    override fun markSocket(fd: Int, mark: Int): Int = 0.also { calls += "mark $fd 0x${mark.toString(16)}" }

    override fun ip(args: List<String>): CommandResult {
        calls += "ip " + args.joinToString(" ")
        // Удалять «повторно, пока удаляется»: второе удаление того же правила — уже нечего.
        if (args.getOrNull(1) == "rule" && args.getOrNull(2) == "del") {
            return if (calls.count { it == "ip " + args.joinToString(" ") } == 1) CommandResult(0, "") else CommandResult(2, "RTNETLINK answers: No such file or directory")
        }
        return if (failOn(args)) CommandResult(2, "RTNETLINK answers: Operation not permitted") else CommandResult(0, "")
    }
}

private fun provider(p: LinuxPlatform) = LinuxTunnelProvider(p, SELF, Logger("test", MemoryLogSink(), { 0L }))

/** Туннель Linux (D-74): команды `ip` один к одному из TunnelSpec и поведение провайдера. */
class LinuxRoutesTest {
    @Test
    fun upFollowsSpecWithMarkFirstAndDnsWithoutExclusions() {
        val cmds = text(LinuxRoutes.up(spec(), ipv6 = true))
        // Устройство: MTU и адреса до подъёма; IPv6 — без DAD (адрес сразу годен).
        assertEquals(
            listOf(
                "link set dev dppass0 mtu 1500",
                "-4 addr add 172.19.0.0/30 dev dppass0",
                "-6 addr add fdfe:dcba:9876::/126 dev dppass0 nodad",
                "link set dev dppass0 up",
            ),
            cmds.take(4),
        )
        for (f in listOf("-4", "-6")) {
            val fam = cmds.filter { it.startsWith("$f ") && "addr" !in it }
            val all = if (f == "-4") "0.0.0.0/0" else "::/0"
            assertTrue("$f route add $all dev dppass0 table 7350" in fam, "маршрут спецификации в таблицу туннеля ($f)")
            // Исключённые — throw в таблице туннеля, и только в ней: в таблице DNS исключений нет.
            val lan = TunnelSpecBuilder.LAN.filter { it.isV4 == (f == "-4") }
            for (r in lan) assertTrue("$f route add throw $r table 7350" in fam, "исключение $r")
            assertTrue(fam.none { "throw" in it && "7351" in it })
            assertTrue("$f route add $all dev dppass0 table 7351" in fam)
            // Правила — после маршрутов, по приоритету: метка ядра → main, DNS → 7351, остальное → 7350.
            val rules = fam.filter { " rule add " in " $it " }
            assertEquals(
                listOf(
                    "$f rule add fwmark 0x7350 lookup main priority 7350",
                    "$f rule add ipproto udp dport 53 lookup 7351 priority 7351",
                    "$f rule add ipproto tcp dport 53 lookup 7351 priority 7352",
                    "$f rule add lookup 7350 priority 7353",
                ),
                rules,
            )
            assertTrue(fam.indexOf(rules.first()) > fam.indexOfLast { " route add " in " $it " }, "правила — после маршрутов ($f)")
        }
    }

    @Test
    fun withoutLanBypassNothingIsThrown() {
        assertTrue(text(LinuxRoutes.up(spec(bypassLan = false), ipv6 = true)).none { "throw" in it })
    }

    @Test
    fun ipv6OffMeansNoIpv6Commands() {
        val cmds = text(LinuxRoutes.up(spec(), ipv6 = false))
        assertTrue(cmds.none { it.startsWith("-6") || "::" in it }, "IPv6 выключен в системе — утекать нечему: $cmds")
        assertTrue("-4 rule add lookup 7350 priority 7353" in cmds)
    }

    @Test
    fun downRemovesRulesBeforeTablesForBothFamilies() {
        val down = LinuxRoutes.down()
        assertTrue(down.all { it.cleanup })
        for (f in listOf("-4", "-6")) {
            val fam = text(down).filter { it.startsWith("$f ") }
            assertEquals(
                listOf(
                    "$f rule del priority 7350", "$f rule del priority 7351", "$f rule del priority 7352", "$f rule del priority 7353",
                    "$f route flush table 7350", "$f route flush table 7351",
                ),
                fam,
            )
        }
        assertTrue(down.filter { "rule" in it.args }.all { it.untilFails })
    }

    @Test
    fun appPolicyOtherThanAllButSelfIsRefused() {
        assertEquals(null, LinuxRoutes.appPolicyProblem(spec(), SELF))
        for (apps in listOf(AppPolicy.OnlyApps(setOf("org.example.browser")), AppPolicy.ExceptApps(setOf(SELF, "org.example.bank")))) {
            val d = LinuxRoutes.appPolicyProblem(spec(apps = apps), SELF)!!
            assertEquals(DiagCode.APP_POLICY_CONFLICT, d.code)
            assertEquals("$.routing.apps", d.path)
        }
    }

    @Test
    fun establishCleansUpFirstThenOpensAndConfigures() {
        runBlocking {
            val p = FakePlatform()
            val handle = assertIs<Outcome.Success<*>>(provider(p).establish(spec())).value as com.dpsmpx.dppass.tunnel.TunnelHandle
            assertEquals(42, handle.fd)
            val open = p.calls.indexOf("open dppass0")
            // Уборка прежнего запуска — до устройства; настройка — после.
            assertTrue(p.calls.subList(0, open).all { " del " in it || " flush " in it }, "до open — только уборка: ${p.calls.subList(0, open)}")
            assertTrue(p.calls.subList(open + 1, p.calls.size).all { " add " in it || " set " in it })
            assertTrue(handle.protect(7))
            assertEquals("mark 7 0x7350", p.calls.last())
            p.calls.clear()
            handle.close()
            handle.close()
            // Правила — раньше fd; повторное закрытие ничего не делает.
            assertEquals("close 42", p.calls.last())
            assertEquals(1, p.calls.count { it.startsWith("close") })
            assertTrue(p.calls.dropLast(1).all { " del " in it || " flush " in it })
        }
    }

    @Test
    fun failedCommandRollsBackAndClosesTun() {
        runBlocking {
            val p = FakePlatform(failOn = { it.contains("ipproto") })
            val f = assertIs<Outcome.Failure>(provider(p).establish(spec()))
            assertEquals(DiagCode.TUN_ESTABLISH_FAILED, f.errors.first().code)
            assertTrue("ipproto" in f.errors.first().message)
            // Вывод ip — причиной, а не в сообщении.
            assertEquals("ip", f.errors.first().causes.single().error?.type)
            val afterFail = p.calls.dropWhile { "ipproto" !in it }.drop(1)
            assertEquals("close 42", afterFail.last())
            assertTrue(afterFail.dropLast(1).all { " del " in it || " flush " in it }, "откат: $afterFail")
        }
    }

    @Test
    fun withoutNetAdminNothingIsTouched() {
        runBlocking {
            val p = FakePlatform(netAdmin = false)
            val f = assertIs<Outcome.Failure>(provider(p).establish(spec()))
            assertEquals(DiagCode.TUN_ESTABLISH_FAILED, f.errors.first().code)
            assertTrue("CAP_NET_ADMIN" in f.errors.first().message)
            assertEquals(emptyList(), p.calls)
        }
    }

    @Test
    fun busyDeviceSaysDppassMayAlreadyRun() {
        runBlocking {
            val p = FakePlatform(tunFd = -16)
            val f = assertIs<Outcome.Failure>(provider(p).establish(spec()))
            assertTrue("уже запущен" in f.errors.first().message)
            assertTrue(p.calls.none { " add " in it })
        }
    }

    @Test
    fun foreignAppPolicyIsRefusedBeforeTouchingSystem() {
        runBlocking {
            val p = FakePlatform()
            val f = assertIs<Outcome.Failure>(provider(p).establish(spec(apps = AppPolicy.OnlyApps(setOf("org.example.browser")))))
            assertEquals(DiagCode.APP_POLICY_CONFLICT, f.errors.first().code)
            assertEquals(emptyList(), p.calls)
        }
    }

    @Test
    fun capEffBit12IsNetAdmin() {
        assertTrue(Capabilities.hasNetAdmin("Name:\tjava\nCapInh:\t0000000000001000\nCapEff:\t0000000000001000\n"))
        assertTrue(Capabilities.hasNetAdmin("CapEff:\t000001fffeffffff\n"))
        assertEquals(false, Capabilities.hasNetAdmin("CapEff:\t0000000000000000\n"))
        assertEquals(false, Capabilities.hasNetAdmin("CapPrm:\t0000000000001000\n"))
        assertEquals(false, Capabilities.hasNetAdmin(null))
    }
}
