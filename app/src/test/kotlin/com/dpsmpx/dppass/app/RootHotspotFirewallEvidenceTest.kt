package com.dpsmpx.dppass.app

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class RootHotspotFirewallEvidenceTest {
    private val identity = RootHotspotInterfaceEvidence.Identity(
        RootHotspotAdmission.Session(9, 12, RootHotspotAdmission.Mode.VPN), "wlan1", "192.168.43.1")
    private val plan = RootHotspotNetworkPlan(identity, "dpgateway", RootHotspotNetworkFixture.slot, "0123456789abcdef")
    private val guard = plan.firewallExpected(false)
    private val active = plan.firewallExpected(true)
    private val forward = RootHotspotFirewallEvidence.Chain.FORWARD4
    private val input = RootHotspotFirewallEvidence.Chain.INPUT4
    private val dns = RootHotspotFirewallEvidence.Chain.DNS4

    private fun dump(chain: RootHotspotFirewallEvidence.Chain,
                     rules: List<String>, tail: List<String> = emptyList()): String =
        (listOf("-P " + chain.chain + " ACCEPT") + rules + tail).joinToString("\n", postfix = "\n")

    @Test fun guardAndAttachedPrefixesMatchInsertionOrder() {
        assertEquals(2, guard.getValue(forward).size)
        assertTrue(guard.getValue(forward).all { it.endsWith("-j DROP") })
        assertEquals(4, active.getValue(forward).size)
        assertTrue(active.getValue(forward).take(2).all { it.endsWith("-j ACCEPT") })
        assertEquals(2, active.getValue(dns).size)
        assertTrue(guard.getValue(dns).isEmpty())
        assertTrue(guard.getValue(input).first().endsWith("-j ACCEPT"))
    }

    @Test fun completeKnownListingsAreAccepted() {
        for (expected in listOf(guard, active)) for ((chain, rules) in expected) {
            assertTrue(RootHotspotFirewallEvidence.matches(chain, dump(chain, rules,
                listOf("-A " + chain.chain + " -j DROP")), rules))
        }
    }

    @Test fun missingReorderedOrPreemptedRulesAreRejected() {
        val rules = active.getValue(forward)
        for (bad in listOf(rules.dropLast(1), rules.reversed(), listOf("-A FORWARD -j ACCEPT") + rules)) {
            assertFalse(RootHotspotFirewallEvidence.matches(forward, dump(forward, bad), rules))
        }
    }

    @Test fun duplicateOrForeignOwnershipIsRejected() {
        val rules = guard.getValue(forward)
        assertFalse(RootHotspotFirewallEvidence.matches(forward, dump(forward, rules + rules.first()), rules))
        assertFalse(RootHotspotFirewallEvidence.matches(forward, dump(forward, rules,
            listOf(rules.first().replace("0123456789abcdef", "fedcba9876543210"))), rules))
    }

    @Test fun truncatedAndMalformedListingsFailClosed() {
        val rules = guard.getValue(forward)
        val raw = dump(forward, rules)
        for (bad in listOf(raw.dropLast(1), "", raw + "error\n", raw + "-P FORWARD DROP\n",
            raw.replace("-P FORWARD ACCEPT", "-P INPUT ACCEPT"), raw + "\u0000\n")) {
            assertFalse(RootHotspotFirewallEvidence.matches(forward, bad, rules))
        }
    }

    @Test fun knownCommentQuotesAndProtocolModuleAreNormalized() {
        val rules = guard.getValue(input)
        val formatted = rules.map { it.replace("--comment dppass-hotspot-0123456789abcdef",
            "--comment \"dppass-hotspot-0123456789abcdef\"").replace("-p udp ", "-p udp -m udp ") }
        assertTrue(RootHotspotFirewallEvidence.matches(input, dump(input, formatted), rules))
    }

    @Test fun completeStableObservationUsesAllFiveChainsTwice() {
        val calls = mutableListOf<List<String>>()
        val observer = RootHotspotFirewallEvidence.Observer { args ->
            calls += args
            val chain = RootHotspotFirewallEvidence.Chain.entries.single { it.command == args }
            RootCommandRunner.CompleteResult(0, dump(chain, guard.getValue(chain)))
        }
        assertTrue(observer.stable(guard))
        assertEquals(10, calls.size)
        assertFalse(observer.stable(guard - forward))
    }

    @Test fun secondPassChangeOrCommandFailureRejectsProof() {
        var calls = 0
        val observer = RootHotspotFirewallEvidence.Observer { args ->
            val chain = RootHotspotFirewallEvidence.Chain.entries.single { it.command == args }
            val tail = if (++calls > 5) listOf("-A " + chain.chain + " -j DROP") else emptyList()
            RootCommandRunner.CompleteResult(0, dump(chain, guard.getValue(chain), tail))
        }
        assertFalse(observer.stable(guard))
        assertFalse(RootHotspotFirewallEvidence.Observer { RootCommandRunner.CompleteResult(1, "") }.stable(guard))
    }

    @Test fun interruptionIsPreserved() {
        try {
            assertFalse(RootHotspotFirewallEvidence.Observer { throw InterruptedException() }.stable(guard))
            assertTrue(Thread.currentThread().isInterrupted)
        } finally { Thread.interrupted() }
    }
}
