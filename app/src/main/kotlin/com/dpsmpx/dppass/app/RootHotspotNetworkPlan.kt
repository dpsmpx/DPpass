package com.dpsmpx.dppass.app

/** Exact per-session network mutations, executed only via the bound claim.
 * The owner supplies independently verified interface/TUN/offload evidence.
 * Shell success alone is not an admission signal. */
internal class RootHotspotNetworkPlan(
    val identity: RootHotspotInterfaceEvidence.Identity,
    tun: String,
    val slot: RootHotspotNetworkSlot,
    generation: String,
) {
    private val input = RootHotspotInputGuard(identity.name, generation)
    private val forward = RootHotspotForwardGuard(identity.name, tun, generation)
    private val routes = RootHotspotRoutes(identity.name, tun, slot.table, slot.priority)
    private val dns = RootHotspotDnsIngress(identity.name, identity.gateway, generation)
    private val marker = "dppass-hotspot-$generation"

    private fun checked(commands: List<String>): String =
        commands.joinToString("\n") { "$it || exit 1" }

    /** Read-only check before admitting any mutation or cleanup intent. */
    fun vacancy(): String = RootHotspotCleanupEvidence(slot.table, slot.priority).script()

    // Recheck under the bound claim immediately before mutation. The outer
    // coordinator checks vacancy separately before marking cleanup intent.
    fun guard(): String = vacancy() + "\n" +
        checked(forward.install + input.install + routes.guard)

    // DNS and route must exist before enabling forwarding to the TUN.
    fun attach(): String = checked(dns.attach + routes.attach + forward.attach)

    /** Exact deletes only. A failed check/delete is not proof of absence.
     * The later complete listing is mandatory. No flush or policy change. */
    private fun removeFirewall(command: String): String {
        val parts = command.split(" ", limit = 5)
        require(parts.size == 5 && parts[3] == "-D")
        val prefix = parts.take(3).joinToString(" ")
        val rule = parts[4]
        return listOf(
            "remaining=32",
            "while $prefix -C $rule 2>/dev/null; do",
            "test \"\$remaining\" -gt 0 || exit 1",
            "$command || exit 1",
            "remaining=\$((remaining-1))",
            "done",
        ).joinToString("\n")
    }

    /** Full listing must positively establish that the forwarding accepts
     * and DNS redirections are gone, and the only IPv4 route is unreachable.
     * Do not remove the default-deny guards here. */
    fun detach(): String = listOf(
        forward.detach.joinToString("\n", transform = ::removeFirewall),
        dns.detach.joinToString("\n", transform = ::removeFirewall),
        routes.detach + " 2>/dev/null || :",
        verifyDetached(),
    ).joinToString("\n")

    private fun verifyDetached(): String = listOf(
        "forward_listing=\$(iptables -t filter -S FORWARD) || exit 1",
        "printf '%s\\n' \"\$forward_listing\" | awk -v marker='$marker' '" +
            "\$1 == \"-P\" && \$2 == \"FORWARD\" && NF == 3 && (\$3 == \"ACCEPT\" || \$3 == \"DROP\") { p++; next } " +
            "\$1 == \"-A\" && \$2 == \"FORWARD\" && NF > 2 { if (index(\$0, marker) && \$NF != \"DROP\") bad=1; next } " +
            "{ bad=1 } END { exit (bad || p != 1) }' || exit 1",
        "dns_listing=\$(iptables -t nat -S PREROUTING) || exit 1",
        "printf '%s\\n' \"\$dns_listing\" | awk -v marker='$marker' '" +
            "\$1 == \"-P\" && \$2 == \"PREROUTING\" && NF == 3 && (\$3 == \"ACCEPT\" || \$3 == \"DROP\") { p++; next } " +
            "\$1 == \"-A\" && \$2 == \"PREROUTING\" && NF > 2 { if (index(\$0, marker)) bad=1; next } " +
            "{ bad=1 } END { exit (bad || p != 1) }' || exit 1",
        "routes=\$(ip -4 route show table " + slot.table + ") || exit 1",
        "test \"\$routes\" = 'unreachable default metric 32767' || exit 1",
    ).joinToString("\n")

    /** Only after independently verified AP shutdown. Retrying a partial
     * installation may see absent resources; exact route deletion failures
     * are tolerated only if the final complete vacancy check succeeds. */
    fun retire(): String = listOf(
        forward.detach.joinToString("\n", transform = ::removeFirewall),
        dns.detach.joinToString("\n", transform = ::removeFirewall),
        routes.detach + " 2>/dev/null || :",
        routes.retireAfterAccessPointStopped.joinToString("\n") { "$it 2>/dev/null || :" },
        input.retireAfterAccessPointStopped.joinToString("\n", transform = ::removeFirewall),
        forward.retireAfterAccessPointStopped.joinToString("\n", transform = ::removeFirewall),
        RootHotspotCleanupEvidence(slot.table, slot.priority).script(),
    ).joinToString("\n")
}
