package com.dpsmpx.dppass.desktop

import com.dpsmpx.dppass.core.Cidr
import com.dpsmpx.dppass.diagnostics.DiagCode
import com.dpsmpx.dppass.diagnostics.Logger
import com.dpsmpx.dppass.diagnostics.MemoryLogSink
import com.dpsmpx.dppass.diagnostics.Outcome
import com.dpsmpx.dppass.engine.SystemTun
import com.dpsmpx.dppass.network.NetworkType
import com.dpsmpx.dppass.routing.AppPolicy
import com.dpsmpx.dppass.storage.KeyWrapper
import com.dpsmpx.dppass.tunnel.Ipv6Mode
import com.dpsmpx.dppass.tunnel.TunnelSpec
import com.dpsmpx.dppass.tunnel.TunnelSpecBuilder
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertIs
import kotlin.test.assertNull
import kotlin.test.assertTrue

private const val SELF = "com.dpsmpx.dppass"

/** TEST-NET-3 (RFC 5737) — мимо туннеля; остальное — в него, как собирает TunnelSpecBuilder без исключающих маршрутов. */
private fun spec(apps: AppPolicy = AppPolicy.ExceptApps(setOf(SELF)), excluded: List<Cidr> = emptyList()) = TunnelSpec(
    address4 = TunnelSpecBuilder.ADDRESS4,
    address6 = TunnelSpecBuilder.ADDRESS6,
    routes = listOf(Cidr.parse("0.0.0.0/1")!!.cidr, Cidr.parse("128.0.0.0/1")!!.cidr, Cidr.ALL_V6),
    excludedRoutes = excluded,
    dnsServers = listOf(TunnelSpecBuilder.TUN_DNS4),
    mtu = 1500,
    apps = apps,
    ipv6Mode = Ipv6Mode.TUNNELED,
)

/** Ответ моста: статус и строки, как у `nativeDefaultRoute`. */
private fun reply(status: Int, text: String): ByteArray = byteArrayOf(status.toByte()) + text.toByteArray(Charsets.UTF_8)

class WindowsTest {
    private val log = Logger("test", MemoryLogSink(), { 0L })

    @Test
    fun adapterTakesHostAddressesRoutesAndInnerDns() {
        val t = assertIs<Outcome.Success<SystemTun>>(WindowsTunnels.systemTun(spec())).value
        // Адрес узла, а не номер сети: его и получает адаптер.
        assertEquals(listOf("172.19.0.1/30", "fdfe:dcba:9876::1/126"), t.addresses.map { it.toString() })
        assertEquals(spec().routes, t.routes)
        assertEquals(listOf(TunnelSpecBuilder.TUN_DNS4), t.dns)
    }

    @Test
    fun excludedRoutesAreRefusedNotDropped() {
        val f = assertIs<Outcome.Failure>(WindowsTunnels.systemTun(spec(excluded = TunnelSpecBuilder.LAN)))
        assertEquals(DiagCode.TUN_ESTABLISH_FAILED, f.errors.first().code)
    }

    @Test
    fun tunnelGivesSystemTunAndNoFd() {
        val t = assertIs<Outcome.Success<DesktopTunnel>>(WindowsTunnels(SELF, log) { true }.establish(spec(), emptyList())).value
        assertNull(t.tunInput)
        assertEquals("172.19.0.1/30", t.systemTun?.addresses?.first().toString())
    }

    @Test
    fun withoutAdministratorNoTunnel() {
        val f = assertIs<Outcome.Failure>(WindowsTunnels(SELF, log) { false }.establish(spec(), emptyList()))
        assertEquals(DiagCode.TUN_ESTABLISH_FAILED, f.errors.first().code)
        assertTrue("администратор" in f.errors.first().message)
    }

    @Test
    fun shareAndAppChoiceAreRefusedWithReason() {
        val tunnels = WindowsTunnels(SELF, log) { true }
        val share = assertIs<Outcome.Failure>(tunnels.establish(spec(), listOf(Cidr.parse("192.0.2.0/24")!!.cidr)))
        assertTrue("раздачи" in share.errors.first().message)
        val apps = assertIs<Outcome.Failure>(tunnels.establish(spec(apps = AppPolicy.OnlyApps(setOf("browser"))), emptyList()))
        assertEquals(DiagCode.APP_POLICY_CONFLICT, apps.errors.first().code)
        assertTrue("на Windows программы не различаются" in apps.errors.first().message)
    }

    @Test
    fun routeReplyGivesNetworkAndAdapterState() {
        val r = WindowsHost.parseRoute(reply(0, "1\nWi-Fi\t192.0.2.1\t2"))
        assertEquals(WindowsNetwork("Wi-Fi", "192.0.2.1", NetworkType.WIFI), r.network)
        assertTrue(r.tunUp)
        assertEquals(NetworkType.MOBILE, WindowsHost.parseRoute(reply(0, "0\nCellular\t\t3")).network?.type)
        assertEquals(NetworkType.ETHERNET, WindowsHost.parseRoute(reply(0, "0\nEthernet\t192.0.2.1\t1")).network?.type)
        assertEquals(NetworkType.OTHER, WindowsHost.parseRoute(reply(0, "0\nX\t192.0.2.1\t0")).network?.type)
    }

    @Test
    fun noRouteOrBridgeRefusalMeansNoNetwork() {
        assertEquals(WindowsHost.Route(null, false), WindowsHost.parseRoute(reply(0, "0")))
        assertEquals(WindowsHost.Route(null, false), WindowsHost.parseRoute(reply(3, "GetIPForwardTable2: отказ")))
        assertEquals(WindowsHost.Route(null, false), WindowsHost.parseRoute(ByteArray(0)))
        // Строка не из трёх полей не разобрана — сети нет, а не «сеть с пустым именем».
        assertNull(WindowsHost.parseRoute(reply(0, "1\nWi-Fi\t192.0.2.1")).network)
    }

    @Test
    fun hostWithoutBridgeKnowsNoNetworkAndNoTunnel() {
        val host = WindowsHost(null, elevated = { false })
        assertNull(host.network())
        assertEquals(false, host.tunnelUp())
        assertEquals(false, host.tunnelAllowed())
        assertTrue("администратора" in host.tunnelRefusal)
        // Чего на Windows нет — окно говорит, а не прячет молча (D-97).
        assertEquals(false, host.checksUnderTunnel)
        assertTrue("раздачи" in host.absent)
    }

    @Test
    fun themeComesFromWindowsAndTrayMayBeAbsent() {
        // Тема приложений Windows: 0 — тёмная, 1 — светлая; не узнать — решают признаки Linux, как без моста.
        assertEquals(true, WindowsHost(null, elevated = { true }, theme = { 0 }).systemDark())
        assertEquals(false, WindowsHost(null, elevated = { true }, theme = { 1 }).systemDark())
        assertNull(WindowsHost(null, elevated = { true }, theme = { -1 }).systemDark())
        assertNull(WindowsHost(null, elevated = { true }).systemDark())
        // Области уведомлений нет — false: окно покажет полосу, а не потеряет порог трафика молча.
        assertEquals(false, TrayNotify { false }.show("DPpass", "порог"))
    }

    @Test
    fun networkKeyDependsOnInterfaceAndGateway() {
        val a = WindowsNetwork("Wi-Fi", "192.0.2.1", NetworkType.WIFI)
        assertEquals(a.key, a.copy().key)
        assertTrue(a.key != a.copy(gateway = "192.0.2.254").key)
    }

    @Test
    fun dpapiWrapperStripsStatusAndReportsLostKey() {
        val w = DpapiKeyWrapper({ reply(0, "sealed:" + String(it)) }, { s -> reply(0, String(s).removePrefix("sealed:")) })
        val sealed = w.wrap("key".toByteArray())
        assertContentEquals("sealed:key".toByteArray(), sealed)
        assertContentEquals("key".toByteArray(), w.unwrap(sealed))
        // Отказ DPAPI при расшифровке — блок чужого пользователя или ПК: ключ потерян, а не «временно недоступен».
        val lost = DpapiKeyWrapper({ it }, { reply(1, "The data is invalid.") })
        assertFailsWith<KeyWrapper.KeyLost> { lost.unwrap(sealed) }
        // Служба DPAPI не ответила — временно: ключ не «потерян», данные не предлагается сбросить.
        assertFailsWith<IllegalStateException> { DpapiKeyWrapper({ it }, { reply(2, "The RPC server is unavailable.") }).unwrap(sealed) }
        assertFailsWith<IllegalStateException> { DpapiKeyWrapper({ reply(1, "отказ") }, { it }).wrap(sealed) }
        assertFailsWith<IllegalStateException> { DpapiKeyWrapper({ it }, { ByteArray(0) }).unwrap(sealed) }
    }

    @Test
    fun networkCheckOnlyWithoutTunnel() {
        var up = false
        val probes = WindowsProbeNetwork { up }
        assertNull(probes.ready())
        up = true
        assertEquals(DiagCode.NETWORK_CHECK_UNAVAILABLE, probes.ready()?.code)
    }

    @Test
    fun windowsPathsUseLocalAppDataAndDll() {
        val local = "C:\\Users\\u\\AppData\\Local"
        assertEquals(local + java.io.File.separator + "DPpass", DesktopPaths.windowsDataDir(mapOf("LOCALAPPDATA" to local), "/home/u").path)
        // Не абсолютный путь — как без переменной: от домашнего каталога.
        assertTrue(DesktopPaths.windowsDataDir(mapOf("LOCALAPPDATA" to "AppData"), "C:\\Users\\u").path.startsWith("C:\\Users\\u\\AppData\\Local"))
        val paths = DesktopPaths(java.io.File("data"), java.io.File("install"), windows = true)
        assertEquals("dppassxray.dll", paths.library.name)
        assertTrue(WindowsHost.isWindows("Windows 11"))
        assertTrue(!WindowsHost.isWindows("Linux"))
    }
}
