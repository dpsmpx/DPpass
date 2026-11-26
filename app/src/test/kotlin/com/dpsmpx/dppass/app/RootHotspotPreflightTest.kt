package com.dpsmpx.dppass.app

import java.io.File
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test

class RootHotspotPreflightTest {
    @Test fun checksOnlyFirewallListingsAndReportsTheFirstFailure() {
        if (!File("/bin/sh").canExecute()) return
        val fake = """
            id() { printf '%s\n' "${'$'}uid"; }
            ip() { return 70; }
            iptables() {
                case "${'$'}*" in
                    '-t filter -S FORWARD') return 0 ;;
                    '-t filter -S INPUT') test "${'$'}input" = yes ;;
                    *) return 70 ;;
                esac
            }
            ip6tables() { test "${'$'}ipv6" = yes && iptables "${'$'}@"; }
        """.trimIndent()
        fun run(uid: Int, ipv6: String, setup: String = ":", input: String = "yes"): Pair<Int, String> {
            val script = "uid=$uid; ipv6=$ipv6; input=$input\n$fake\n$setup\n" + RootHotspotPreflight.script()
            val result = RootCommandRunner.run(listOf("/bin/sh", "-c", script))
            return result.exitCode to result.outputTail.trim()
        }
        assertEquals(1 to "root_required", run(2000, "yes"))
        assertEquals(1 to "missing_ip", run(0, "yes", "unset -f ip; PATH=/nonexistent"))
        assertEquals(1 to "forward_unavailable_iptables", run(0, "yes", "iptables() { return 1; }"))
        assertEquals(1 to "forward_unavailable_ip6tables", run(0, "no"))
        assertEquals(1 to "input_unavailable_iptables", run(0, "yes", input = "no"))
        assertEquals(1 to "input_unavailable_ip6tables", run(0, "yes", "ip6tables() { test \"\$4\" = FORWARD; }"))
        assertEquals(0 to "baseline_available", run(0, "yes"))
    }
}
