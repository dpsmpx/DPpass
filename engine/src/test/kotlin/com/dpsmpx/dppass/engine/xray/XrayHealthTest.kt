package com.dpsmpx.dppass.engine.xray

import com.dpsmpx.dppass.core.Endpoint
import com.dpsmpx.dppass.core.Host
import com.dpsmpx.dppass.core.IpAddress
import com.dpsmpx.dppass.diagnostics.DiagCode
import com.dpsmpx.dppass.diagnostics.Outcome
import com.dpsmpx.dppass.routing.DnsPolicy
import com.dpsmpx.dppass.routing.DnsRoute
import com.dpsmpx.dppass.routing.DnsServer
import com.dpsmpx.dppass.routing.DnsTransport
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNull

/** Куда идёт проба здоровья (D-32): DNS-сервер конфигурации через туннель. */
class XrayHealthTest {
    private fun ip(s: String) = Endpoint(Host.Ip(IpAddress.parse(s)!!), 53)
    private val doh = DnsServer("doh", DnsTransport.Https("https://dns.example.net/dns-query"), DnsRoute.TUNNEL)
    private val udp6 = DnsServer("udp6", DnsTransport.Udp(ip("2001:db8::53")), DnsRoute.TUNNEL)
    private val tcp = DnsServer("tcp", DnsTransport.Tcp(ip("192.0.2.53")), DnsRoute.TUNNEL)
    private val dot = DnsServer("dot", DnsTransport.Tls(ip("192.0.2.54"), "dns.example.net"), DnsRoute.TUNNEL)
    private val direct = DnsServer("direct", DnsTransport.Https("https://dns.example.org/dns-query"), DnsRoute.DIRECT)
    private val system = DnsServer("system", DnsTransport.System, DnsRoute.DIRECT)

    @Test
    fun defaultTunnelServerIsPreferred() {
        assertEquals("udp6" to "udp://[2001:db8::53]:53", XrayHealth.target(DnsPolicy(listOf(doh, udp6), "udp6"))?.let { it.first.id to it.second })
        assertEquals("doh" to "https://dns.example.net/dns-query", XrayHealth.target(DnsPolicy(listOf(doh, udp6), "doh"))?.let { it.first.id to it.second })
    }

    @Test
    fun directDefaultFallsBackToFirstTunnelServer() {
        // Сервер по умолчанию мимо туннеля проверить сервер профиля не может.
        assertEquals("tcp://192.0.2.53:53", XrayHealth.target(DnsPolicy(listOf(direct, dot, tcp), "direct"))?.second)
    }

    @Test
    fun withoutTunnelServerHealthIsSkippedLoudly() {
        assertNull(XrayHealth.target(DnsPolicy(listOf(direct, system), "direct")))
        assertNull(XrayHealth.target(DnsPolicy(listOf(dot, system), "dot")), "DoT ядро не умеет — проба через него не пройдёт")
        val r = assertIs<Outcome.Success<Unit>>(XrayHealth.skipped())
        assertEquals(DiagCode.HEALTH_CHECK_SKIPPED, r.diagnostics.single().code)
    }
}
