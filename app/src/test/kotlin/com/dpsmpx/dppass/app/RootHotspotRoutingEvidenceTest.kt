package com.dpsmpx.dppass.app

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class RootHotspotRoutingEvidenceTest {
    private val plan = RootHotspotNetworkPlan(RootHotspotInterfaceEvidence.Identity(
        RootHotspotAdmission.Session(9, 12, RootHotspotAdmission.Mode.VPN), "wlan1", "192.168.43.1"),
        "dpgateway", RootHotspotNetworkFixture.slot, "0123456789abcdef")
    private val local = "0: from all lookup local\n"
    private val lookup = "400: from all iif wlan1 lookup 12000\n"
    private val terminal = "401: from all iif wlan1 unreachable\n"
    private val unreachable = "unreachable default metric 32767\n"
    private val attached = "default dev dpgateway scope link metric 100\n" + unreachable

    @Test fun exactRulesBothFamilies() {
        assertTrue(RootHotspotRoutingEvidence.rules(plan, false, local + lookup + terminal, lookup))
        assertTrue(RootHotspotRoutingEvidence.rules(plan, true, local + terminal, ""))
    }

    @Test fun earlierPolicyRejectedEvenIfExpectedRulesRemain() {
        assertFalse(RootHotspotRoutingEvidence.rules(plan, false,
            local + "100: from all lookup main\n" + lookup + terminal, lookup))
    }

    @Test fun missingDuplicateWrongInterfaceOrPriorityRejected() {
        for (raw in listOf(local + lookup, local + lookup + lookup + terminal,
            local + lookup.replace("wlan1", "wlan2") + terminal,
            local + lookup + terminal.replace("401", "402"))) {
            assertFalse(RootHotspotRoutingEvidence.rules(plan, false, raw, lookup))
        }
    }

    @Test fun aliasesAndExtraTableReferencesRejected() {
        assertFalse(RootHotspotRoutingEvidence.rules(plan, false, local + lookup + terminal,
            lookup + "9000: from all lookup 12000\n"))
        assertFalse(RootHotspotRoutingEvidence.rules(plan, false,
            local + lookup.replace("12000", "guest") + terminal, lookup))
    }

    @Test fun invalidOrTruncatedRuleOutputRejected() {
        for (raw in listOf("", local + lookup + terminal.dropLast(1), "error\n",
            local + local + lookup + terminal, local + lookup + terminal + "bad\n")) {
            assertFalse(RootHotspotRoutingEvidence.rules(plan, false, raw, lookup))
        }
    }

    @Test fun defaultRouteAndUnreachableFallbackAreRequired() {
        assertTrue(RootHotspotRoutingEvidence.routes(plan, false, false, unreachable))
        assertTrue(RootHotspotRoutingEvidence.routes(plan, false, true, attached))
        assertFalse(RootHotspotRoutingEvidence.routes(plan, false, true, unreachable))
        assertFalse(RootHotspotRoutingEvidence.routes(plan, false, false, attached))
        assertFalse(RootHotspotRoutingEvidence.routes(plan, false, true, attached.replace("dpgateway", "rmnet0")))
    }

    @Test fun rejectsExtraRoutesAndAnyIpv6TableContent() {
        assertFalse(RootHotspotRoutingEvidence.routes(plan, false, true, attached + "default dev rmnet0\n"))
        assertTrue(RootHotspotRoutingEvidence.routes(plan, true, true, ""))
        assertFalse(RootHotspotRoutingEvidence.routes(plan, true, true, "default dev rmnet0\n"))
    }

    @Test fun onlyFixedReadOperationsAndCanonicalReservedTableAllowed() {
        assertTrue(RootHotspotRoutingEvidence.allowed(listOf("ip", "-4", "rule", "show")))
        assertTrue(RootHotspotRoutingEvidence.allowed(listOf("ip", "-6", "route", "show", "table", "12000")))
        for (args in listOf(listOf("ip", "-4", "route", "flush", "table", "12000"),
            listOf("ip", "-4", "route", "show", "table", "012000"),
            listOf("ip", "-4", "route", "show", "table", "all"),
            listOf("ip", "-4", "route", "show", "table", "20001"))) {
            assertFalse(RootHotspotRoutingEvidence.allowed(args))
        }
    }

    private fun output(args: List<String>): String = when {
        args[2] == "route" -> if (args[1] == "-4") unreachable else ""
        args.size == 4 -> local + (if (args[1] == "-4") lookup else "") + terminal
        else -> if (args[1] == "-4") lookup else ""
    }

    @Test fun stableReadUsesSixQueriesTwice() {
        var calls = 0
        val observer = RootHotspotRoutingEvidence.Observer { args ->
            calls++
            RootCommandRunner.CompleteResult(0, output(args))
        }
        assertTrue(observer.stable(plan, false))
        assertEquals(12, calls)
    }

    @Test fun changedSecondReadAndCommandFailureRejectEvidence() {
        var calls = 0
        val observer = RootHotspotRoutingEvidence.Observer { args ->
            calls++
            val change = if (calls > 6 && args.size == 4) "9000: from all lookup main\n" else ""
            RootCommandRunner.CompleteResult(0, output(args) + change)
        }
        assertFalse(observer.stable(plan, false))
        assertFalse(RootHotspotRoutingEvidence.Observer { RootCommandRunner.CompleteResult(1, "") }.stable(plan, false))
    }

    @Test fun interruptedObservationPreservesInterrupt() {
        try {
            assertFalse(RootHotspotRoutingEvidence.Observer { throw InterruptedException() }.stable(plan, false))
            assertTrue(Thread.currentThread().isInterrupted)
        } finally { Thread.interrupted() }
    }
}
