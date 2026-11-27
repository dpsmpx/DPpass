package com.dpsmpx.dppass.app

/** Positive firewall evidence for the exact session, not offload or routing
 * proof. Accept only complete built-in chain listings with a single policy.
 * Rules installed at position 1 must occupy the corresponding prefix;
 * unrelated rules are allowed only below that prefix. Unknown formatting
 * fails closed. Never execute text read from the kernel. */
internal object RootHotspotFirewallEvidence {
    enum class Chain(val tool: String, val table: String, val chain: String) {
        FORWARD4("iptables", "filter", "FORWARD"),
        FORWARD6("ip6tables", "filter", "FORWARD"),
        INPUT4("iptables", "filter", "INPUT"),
        INPUT6("ip6tables", "filter", "INPUT"),
        DNS4("iptables", "nat", "PREROUTING");
        val command: List<String> get() = listOf(tool, "-t", table, "-S", chain)
    }

    private val token = Regex("[A-Za-z0-9_./:+-]+")
    private val marker = Regex("dppass-hotspot-[a-f0-9]{16}")
    private const val MAX = 256 * 1024

    /** iptables -S may quote comment values and insert protocol modules.
     * Only normalize those known renderings of our own simple rules. */
    private fun canonical(rule: String): String? {
        val parts = rule.split(' ').toMutableList()
        if (parts.any { it.isEmpty() }) return null
        val comment = parts.indexOf("--comment")
        if (comment >= 0 && comment + 1 < parts.size) {
            val value = parts[comment + 1]
            if (value.length >= 2 && value.first() == '"' && value.last() == '"') {
                parts[comment + 1] = value.substring(1, value.length - 1)
            }
        }
        if (parts.any { !it.matches(token) }) return null
        val protocol = parts.indexOf("-p").let { if (it < 0) null else parts.getOrNull(it + 1) }
        if (protocol in setOf("tcp", "udp")) {
            val module = parts.indices.firstOrNull { parts[it] == "-m" && parts.getOrNull(it + 1) == protocol }
            if (module != null) {
                parts.removeAt(module)
                parts.removeAt(module)
            }
        }
        // -S may reorder -m comment after -m udp/tcp. Treat only the exact
        // validated ownership marker as an order-independent match clause.
        val m = parts.indexOf("--comment")
        if (m < 2 || parts[m - 2] != "-m" || parts[m - 1] != "comment" ||
            parts.getOrNull(m + 1)?.matches(marker) != true) return null
        val tag = parts[m + 1]
        repeat(4) { parts.removeAt(m - 2) }
        val jump = parts.indexOf("-j")
        if (jump < 0) return null
        parts.addAll(jump, listOf("-m", "comment", "--comment", tag))
        return parts.joinToString(" ")
    }

    /** Convert trusted -I CHAIN 1 plans to expected -A chain prefix.
     * Insertions reverse chronological order independently per chain. */
    fun expected(inserts: List<String>): Map<Chain, List<String>> {
        val expected = Chain.entries.associateWith { mutableListOf<String>() }
        for (line in inserts) {
            val parts = line.split(" ", limit = 7)
            require(parts.size == 7 && parts[1] == "-t" && parts[3] == "-I" && parts[5] == "1")
            val chain = Chain.entries.single { it.tool == parts[0] && it.table == parts[2] && it.chain == parts[4] }
            val rule = requireNotNull(canonical("-A " + chain.chain + " " + parts[6]))
            expected.getValue(chain).add(0, rule)
        }
        return expected.mapValues { it.value.toList() }
    }

    fun matches(chain: Chain, raw: String, expected: List<String>): Boolean {
        if (raw.length > MAX || !raw.endsWith('\n') || '\r' in raw || '\u0000' in raw) return false
        val lines = raw.dropLast(1).split('\n')
        if (lines.firstOrNull() !in setOf("-P " + chain.chain + " ACCEPT", "-P " + chain.chain + " DROP")) return false
        val rules = lines.drop(1)
        if (rules.any { !it.startsWith("-A " + chain.chain + " ") || it.length <= chain.chain.length + 4 }) return false
        if (rules.size < expected.size) return false
        if (rules.take(expected.size).map(::canonical) != expected) return false
        // Includes other generations, duplicates and unrecognized owned rules.
        return rules.drop(expected.size).none { "dppass-hotspot-" in it }
    }

    class Observer(private val read: (List<String>) -> RootCommandRunner.CompleteResult) {
        fun stable(expected: Map<Chain, List<String>>): Boolean {
            if (expected.keys != Chain.entries.toSet()) return false
            return try {
                val first = sample(expected) ?: return false
                first == sample(expected)
            } catch (_: InterruptedException) {
                Thread.currentThread().interrupt()
                false
            } catch (_: Exception) { false }
        }

        private fun sample(expected: Map<Chain, List<String>>): Map<Chain, String>? {
            val result = linkedMapOf<Chain, String>()
            for (chain in Chain.entries) {
                val reply = read(chain.command)
                if (reply.exitCode != 0 || !matches(chain, reply.stdout, expected.getValue(chain))) return null
                result[chain] = reply.stdout
            }
            return result
        }
    }
}
