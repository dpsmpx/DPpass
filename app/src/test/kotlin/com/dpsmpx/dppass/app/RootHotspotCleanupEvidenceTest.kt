package com.dpsmpx.dppass.app

import java.io.File
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class RootHotspotCleanupEvidenceTest {
    private val evidence = RootHotspotCleanupEvidence(12000, 400)

    private val baseline = """
        iptables() {
            test "${'$'}1" = -t && test "${'$'}3" = -S || return 91
            printf '%s\n' "-P ${'$'}4 ACCEPT" "-A ${'$'}4 -j DROP"
        }
        ip6tables() { iptables "${'$'}@"; }
        ip() {
            case "${'$'}*" in
                '-4 rule show'|'-6 rule show') printf '%s\n' '0: from all lookup local' '32766: from all lookup main';;
                '-4 rule show table 12000'|'-6 rule show table 12000'|'-4 route show table 12000'|'-6 route show table 12000') :;;
                *) return 91;;
            esac
        }
    """.trimIndent()

    private fun run(override: String = ""): Int =
        RootCommandRunner.run(listOf("/bin/sh", "-c", baseline + "\n" + override + "\n" + evidence.script()),
            timeoutMillis = 5000).exitCode

    @Test fun validCleanListsPassAndOnlyReadCommandsAreUsed() {
        if (!File("/bin/sh").canExecute()) return
        assertEquals(0, run())
        assertFalse(evidence.script().contains(" -D "))
        assertFalse(evidence.script().contains(" flush "))
    }

    @Test fun ownedAndUnexpectedGenerationRulesBlockBothFamilies() {
        if (!File("/bin/sh").canExecute()) return
        for (chain in listOf("INPUT", "FORWARD", "PREROUTING")) {
            val stub = "iptables() { echo \"-P \$4 ACCEPT\"; if test \"\$4\" = '$chain'; then " +
                "echo \"-A \$4 -m comment --comment dppass-hotspot-ffffffffffffffff -j DROP\"; fi; }"
            assertFalse(run(stub) == 0)
        }
        assertFalse(run("ip6tables() { echo \"-P \$4 ACCEPT\"; echo \"-A \$4 -m comment --comment dppass-hotspot-other -j DROP\"; }") == 0)
    }

    @Test fun unavailableOrMalformedFirewallListingFailsClosed() {
        if (!File("/bin/sh").canExecute()) return
        for (stub in listOf("return 2", "return 0", "echo '-P OUTPUT ACCEPT'",
            "echo \"-P \$4 UNKNOWN\"", "echo \"-P \$4 ACCEPT\"; echo \"-P \$4 DROP\"",
            "echo \"-P \$4 ACCEPT\"; echo '-A OUTPUT -j DROP'")) {
            assertFalse(run("ip6tables() { $stub; }") == 0)
        }
    }

    @Test fun reservedPrioritiesAndInvalidRuleListingsBlockRetirement() {
        if (!File("/bin/sh").canExecute()) return
        for (row in listOf("400: from all lookup guest", "401: from all unreachable", "malformed")) {
            assertFalse(run("ip() { echo '0: from all lookup local'; echo '$row'; }") == 0)
        }
        assertFalse(run("ip() { return 0; }") == 0)
    }

    @Test fun numericTableQueriesMustSucceedAndBeEmptyForBothFamilies() {
        if (!File("/bin/sh").canExecute()) return
        for (command in listOf("-4 rule show table 12000", "-6 rule show table 12000",
            "-4 route show table 12000", "-6 route show table 12000")) {
            for (result in listOf("return 2", "echo 'unreachable default'")) {
                val stub = "ip() { case \"\$*\" in '$command') $result;; " +
                    "'-4 rule show'|'-6 rule show') echo '0: from all lookup local';; *) :;; esac; }"
                assertFalse(run(stub) == 0)
            }
        }
    }

    @Test fun secondPassCanRejectNewResidualAndUnsafeIdsAreRefused() {
        if (!File("/bin/sh").canExecute()) return
        assertFalse(run("iptables() { echo \"-P \$4 ACCEPT\"; if test \"\$pass\" = 2; then " +
            "echo \"-A \$4 -m comment --comment dppass-hotspot-residual -j DROP\"; fi; }") == 0)
        assertTrue(runCatching { RootHotspotCleanupEvidence(9999, 400) }.isFailure)
        assertTrue(runCatching { RootHotspotCleanupEvidence(12000, 1000) }.isFailure)
    }
}
