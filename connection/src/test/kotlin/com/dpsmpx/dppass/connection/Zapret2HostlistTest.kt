package com.dpsmpx.dppass.connection

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class Zapret2HostlistTest {
    @Test fun normalizesAndDeduplicatesDomains() {
        val list = Zapret2Hostlist.parse("# local list\n Example.ORG \nsub.example.org\nexample.org\n").getOrThrow()
        assertEquals(listOf("example.org", "sub.example.org"), list.domains)
        assertEquals(list, Zapret2Hostlist.parse(list.format()).getOrThrow())
    }

    @Test fun emptyListExplicitlyMeansNoFiltering() {
        assertTrue(Zapret2Hostlist.parse(" \n# comment\n").getOrThrow().isEmpty)
    }

    @Test fun unsafeOrInvalidInputIsRejected() {
        listOf("../etc/passwd", "--new", "example.org;id", "https://example.org",
            "*.example.org", "exa mple.org", "localhost", "192.168.1.1",
            "a..org", "bad_domain.org", "a".repeat(64) + ".org").forEach {
            assertTrue(Zapret2Hostlist.parse(it).isFailure, "Must reject: $it")
        }
    }

    @Test fun limitsAreEnforced() {
        assertTrue(Zapret2Hostlist.parse("x".repeat(65_537)).isFailure)
        val many = (0..2_048).joinToString("\n") { "x$it.example.org" }
        assertTrue(Zapret2Hostlist.parse(many).isFailure)
    }

    @Test fun noRootStrategyFailsToDefaultForUnknownValues() {
        Zapret2VpnStrategy.entries.forEach { assertEquals(it, Zapret2VpnStrategy.of(it.wire)) }
        assertEquals(Zapret2VpnStrategy.FAKE_TTL_3, Zapret2VpnStrategy.of("inject"))
        assertFalse(Zapret2VpnStrategy.of(null) == Zapret2VpnStrategy.DISORDER)
    }
}
