package com.dpsmpx.dppass.app

import java.io.File
import java.nio.file.Files
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class RootFirewallCleanupTest {
    @Test fun listingMustProveAbsenceAndDeletionIsBounded() {
        if (!File("/bin/sh").canExecute()) return
        val dir = Files.createTempDirectory("dppass-firewall-cleanup").toFile()
        val state = File(dir, "state")
        val intent = File(dir, "ipv6.intent")
        val rule = "-p tcp -j NFQUEUE --queue-num 20529"
        val policy = "-P OUTPUT ACCEPT"
        val unrelated = "-A OUTPUT -p udp -j ACCEPT"
        val owned = "-A OUTPUT $rule"
        val unexpected = "-A OUTPUT -p udp -j NFQUEUE --queue-num 20529"
        val fixture = """
            iptables() {
                case "${'$'}3" in
                    -S) cat '${state.path}';;
                    -C) grep -Fxq -- '-A OUTPUT $rule' '${state.path}';;
                    -D) grep -Fvx -- '-A OUTPUT $rule' '${state.path}' > '${state.path}.tmp'; mv '${state.path}.tmp' '${state.path}';;
                    *) return 2;;
                esac
            }
        """.trimIndent() + "\n"
        fun run(prefix: String, script: String) = RootCommandRunner.run(
            listOf("/bin/sh", "-c", prefix + script), timeoutMillis = 5000,
        )
        val cleanup = RootFirewallCleanup.remove(RootFirewallCleanup.Kind.PACKET, "iptables", listOf(rule))
        try {
            state.writeText("$policy\n$owned\n$unrelated\n")
            assertEquals(0, run(fixture, cleanup).exitCode)
            assertEquals("$policy\n$unrelated\n", state.readText())
            state.writeText("$policy\n$unexpected\n$unrelated\n")
            assertFalse(run(fixture, cleanup).exitCode == 0)
            assertTrue(state.readText().contains(unexpected))

            state.writeText("$policy\n$owned\n")
            val failedCheck = fixture.replace("-C) grep", "-C) return 2; grep")
            assertFalse(run(failedCheck, cleanup).exitCode == 0)
            assertEquals("$policy\n$owned\n", state.readText())
            val stuck = "iptables() { case \"\$3\" in -S) cat '${state.path}';; -C|-D) return 0;; esac; }\n"
            assertFalse(run(stuck, cleanup).exitCode == 0)

            val unavailable = "ip6tables() { return 2; }\n"
            val ipv6 = RootFirewallCleanup.remove(RootFirewallCleanup.Kind.PACKET, "ip6tables", listOf(rule),
                optional = true, intentFile = intent.path)
            assertEquals(0, run(unavailable, ipv6).exitCode)
            assertEquals(0, run("", RootFirewallCleanup.markIntent(intent.path)).exitCode)
            assertFalse(run(unavailable, ipv6).exitCode == 0)
            assertTrue(intent.exists())
            for (malformed in listOf("", "$unrelated\n", "-P OUTPUT UNKNOWN\n",
                "$policy\n$policy\n", "$policy\n-A INPUT -j ACCEPT\n")) {
                state.writeText(malformed)
                assertFalse(run(fixture, cleanup).exitCode == 0)
                assertFalse(run(fixture.replace("iptables()", "ip6tables()"), ipv6).exitCode == 0)
                assertTrue(intent.exists())
                assertEquals(malformed, state.readText())
            }
            // First listing is valid; the final listing cannot confirm absence.
            state.writeText("$policy\n$owned\n")
            val invalidAfterDelete = fixture.replace(
                "mv '" + state.path + ".tmp' '" + state.path + "'",
                ": > '" + state.path + "'")
            assertFalse(run(invalidAfterDelete.replace("iptables()", "ip6tables()"), ipv6).exitCode == 0)
            assertTrue(intent.exists())
            state.writeText("$policy\n$unrelated\n")
            assertEquals(0, run(fixture.replace("iptables()", "ip6tables()"), ipv6).exitCode)
            assertFalse(intent.exists())
        } finally {
            dir.deleteRecursively()
        }
    }
}
