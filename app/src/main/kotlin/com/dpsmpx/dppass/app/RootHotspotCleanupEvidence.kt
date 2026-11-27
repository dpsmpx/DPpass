package com.dpsmpx.dppass.app

/**
 * D-120: read-only postcondition for the planned hotspot firewall and routing
 * resources. Caller holds shared ROOT ownership and must already have
 * independent positive AP, request and egress shutdown evidence.
 *
 * A successful deletion or failed lookup is not evidence of absence.
 * Unsupported listing commands (including kernels reporting an absent route
 * table as an error) deliberately prevent retirement. This is not an atomic
 * snapshot or proof against non-cooperating writers, offload or other tables.
 */
internal class RootHotspotCleanupEvidence(private val table: Int, private val priority: Int) {
    init {
        require(table in 10_000..20_000 && priority in 100..999)
    }

    /** Require valid built-in policies and no hotspot marker in any planned chain.
     * Check all generations, not just the current token. Do not delete anything. */
    private fun firewall(): String = """
        check_chain() {
            listing=${'$'}("${'$'}1" -t "${'$'}2" -S "${'$'}3") || return 1
            printf '%s\n' "${'$'}listing" | awk -v chain="${'$'}3" '
                ${'$'}1 == "-P" && ${'$'}2 == chain && NF == 3 && (${'$'}3 == "ACCEPT" || ${'$'}3 == "DROP") { policies++; next }
                ${'$'}1 == "-A" && ${'$'}2 == chain && NF > 2 {
                    if (index(${'$'}0, "dppass-hotspot-") != 0) bad=1
                    next
                }
                { bad=1 }
                END { exit (bad || policies != 1) }
            ' || return 1
        }
        check_chain iptables filter INPUT || exit 1
        check_chain iptables filter FORWARD || exit 1
        check_chain ip6tables filter INPUT || exit 1
        check_chain ip6tables filter FORWARD || exit 1
        check_chain iptables nat PREROUTING || exit 1
    """.trimIndent()

    /** Filter by numeric table using the kernel/ip command, not textual aliases.
     * Also inspect both reserved priorities in complete rule lists. */
    private fun routing(): String = """
        for family in -4 -6; do
            rules=${'$'}(ip "${'$'}family" rule show) || exit 1
            printf '%s\n' "${'$'}rules" | awk -v p=$priority '
                ${'$'}1 !~ /^[0-9]+:${'$'}/ || NF < 2 { bad=1 }
                ${'$'}1 == "0:" { baseline++ }
                ${'$'}1 == p ":" || ${'$'}1 == (p+1) ":" { bad=1 }
                END { exit (bad || baseline != 1) }
            ' || exit 1
            selected=${'$'}(ip "${'$'}family" rule show table $table) || exit 1
            test -z "${'$'}selected" || exit 1
            routes=${'$'}(ip "${'$'}family" route show table $table) || exit 1
            test -z "${'$'}routes" || exit 1
        done
    """.trimIndent()

    /** No mutation. Repeat to reject a residual appearing in the second pass. */
    fun script(): String = listOf(
        "(", "set -eu", "export LC_ALL=C",
        "for pass in 1 2; do", firewall(), routing(), "done", ") || exit 1",
    ).joinToString("\n")
}
