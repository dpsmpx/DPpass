package com.dpsmpx.dppass.engine.xray

import kotlin.test.Test
import kotlin.test.assertEquals

/** Выход IPv6 через сервер (D-66): порядок проб и когда «не выпускает». */
class XrayIpv6Test {
    private fun run(vararg answers: DnsProbeOutcome): Pair<Ipv6Check, List<String>> {
        val asked = mutableListOf<String>()
        val queue = ArrayDeque(answers.toList())
        val check = XrayIpv6.probe { target ->
            asked += target
            DnsProbeResult(queue.removeFirst(), 100 * asked.size, 0, "")
        }
        assertEquals(0, queue.size, "все ответы использованы: $asked")
        return check to asked
    }

    @Test
    fun firstAnswerOverIpv6IsEnough() {
        val (c, asked) = run(DnsProbeOutcome.OK)
        assertEquals(Ipv6Egress.FORWARDED, c.egress)
        assertEquals(listOf(XrayIpv6.TARGETS[0]), asked)

        val (second, asked2) = run(DnsProbeOutcome.UNREACHABLE, DnsProbeOutcome.OK)
        assertEquals(Ipv6Egress.FORWARDED, second.egress, "один ориентир недоступен — не повод говорить «нет IPv6»")
        assertEquals(XrayIpv6.TARGETS, asked2)
    }

    @Test
    fun notForwardedOnlyWhenIpv4ThroughTheSameServerWorks() {
        val (c, asked) = run(DnsProbeOutcome.UNREACHABLE, DnsProbeOutcome.STALLED, DnsProbeOutcome.OK)
        assertEquals(Ipv6Egress.NOT_FORWARDED, c.egress)
        assertEquals(XrayIpv6.TARGETS + XrayIpv6.CONTROL, asked)
        assertEquals(listOf(DnsProbeOutcome.UNREACHABLE, DnsProbeOutcome.STALLED, DnsProbeOutcome.OK), c.outcomes)
        assertEquals(listOf(100, 200, 300), c.results.map { it.elapsedMillis }, "время каждой пробы — для журнала")

        // Сервер не отвечает и по IPv4 — это сбой сервера, а не отсутствие IPv6.
        assertEquals(Ipv6Egress.UNKNOWN, run(DnsProbeOutcome.UNREACHABLE, DnsProbeOutcome.UNREACHABLE, DnsProbeOutcome.STALLED).first.egress)
    }

    @Test
    fun answersNotAboutTheIpv6PathStopAtOnce() {
        for (o in listOf(DnsProbeOutcome.BAD_ANSWER, DnsProbeOutcome.NOT_RUNNING, DnsProbeOutcome.CONTRACT, DnsProbeOutcome.TLS)) {
            val (c, asked) = run(o)
            assertEquals(Ipv6Egress.UNKNOWN, c.egress, o.name)
            assertEquals(1, asked.size, o.name)
        }
    }

    @Test
    fun targetsAreIpv6LiteralsOverTcpAndControlIsIpv4() {
        assertEquals(2, XrayIpv6.TARGETS.size)
        XrayIpv6.TARGETS.forEach { assert(it.startsWith("tcp://[") && it.endsWith("]:53")) { it } }
        assert(XrayIpv6.CONTROL.matches(Regex("""tcp://\d+\.\d+\.\d+\.\d+:53"""))) { XrayIpv6.CONTROL }
    }
}
