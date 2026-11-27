package com.dpsmpx.dppass.app

/**
 * Read-only proof of exact reserved policy rules and route-table contents.
 * Unknown aliases/renderings, earlier policy rules and incomplete snapshots
 * fail closed. This does not prove offload, netd exclusion, or packet delivery.
 */
internal object RootHotspotRoutingEvidence {
    private const val MAX = 256 * 1024
    private val spaces = Regex("[ \t]+")
    private val priority = Regex("([0-9]+): (.+)")

    fun allowed(args: List<String>): Boolean {
        if (args.size !in setOf(4, 6) || args[0] != "ip" || args[1] !in setOf("-4", "-6")) return false
        if (args.size == 4) return args[2] == "rule" && args[3] == "show"
        val table = args[5].toIntOrNull() ?: return false
        return args[2] in setOf("rule", "route") && args[3] == "show" && args[4] == "table" &&
            table in 10_000..20_000 && table.toString() == args[5]
    }

    private fun lines(raw: String): List<String>? {
        if (raw.length > MAX || '\u0000' in raw || '\r' in raw) return null
        if (raw.isEmpty()) return emptyList()
        if (!raw.endsWith('\n')) return null
        return raw.dropLast(1).split('\n').map { line ->
            if (line.isBlank() || line.any { it < ' ' && it != '\t' }) return null
            line.trim().replace(spaces, " ")
        }
    }

    private fun expectedRules(plan: RootHotspotNetworkPlan, ipv6: Boolean): List<String> {
        val p = plan.slot.priority
        val downstream = plan.identity.name
        val terminal = (p + 1).toString() + ": from all iif $downstream unreachable"
        return if (ipv6) listOf(terminal) else listOf(
            "$p: from all iif $downstream lookup " + plan.slot.table, terminal,
        )
    }

    fun rules(plan: RootHotspotNetworkPlan, ipv6: Boolean, all: String, selected: String): Boolean {
        val rows = lines(all) ?: return false
        val selectedRows = lines(selected) ?: return false
        val expected = expectedRules(plan, ipv6)
        val first = rows.firstOrNull() ?: return false
        if (first != "0: from all lookup local") return false
        val reserved = mutableListOf<String>()
        var previous = -1
        for (row in rows) {
            val match = priority.matchEntire(row) ?: return false
            val p = match.groupValues[1].toIntOrNull() ?: return false
            if (p.toString() != match.groupValues[1] || p < previous) return false
            if (p == 0 && previous == 0) return false
            previous = p
            // Do not infer that an earlier unfamiliar policy is harmless.
            if (p in 1 until plan.slot.priority) return false
            if (p == plan.slot.priority || p == plan.slot.priority + 1) reserved += row
        }
        if (reserved != expected) return false
        // Numeric selector independently rejects aliases or additional rules
        // referencing the reserved table, including at higher priorities.
        return selectedRows == if (ipv6) emptyList() else listOf(expected.first())
    }

    fun routes(plan: RootHotspotNetworkPlan, ipv6: Boolean, attached: Boolean, raw: String): Boolean {
        val rows = lines(raw) ?: return false
        if (ipv6) return rows.isEmpty()
        val unreachable = "unreachable default metric 32767"
        if (!attached) return rows == listOf(unreachable)
        val route = "default dev " + plan.tun
        return rows.size == 2 && rows.count { it == unreachable } == 1 &&
            rows.count { it == "$route scope link metric 100" || it == "$route metric 100" } == 1
    }

    class Observer(private val read: (List<String>) -> RootCommandRunner.CompleteResult) {
        fun stable(plan: RootHotspotNetworkPlan, attached: Boolean): Boolean = try {
            val first = sample(plan, attached)
            first != null && first == sample(plan, attached)
        } catch (_: InterruptedException) {
            Thread.currentThread().interrupt()
            false
        } catch (_: Exception) { false }

        private fun sample(plan: RootHotspotNetworkPlan, attached: Boolean): List<String>? {
            val result = mutableListOf<String>()
            val table = plan.slot.table.toString()
            fun query(args: List<String>): String? {
                check(allowed(args))
                val reply = read(args)
                if (reply.exitCode != 0) return null
                result += reply.stdout
                return reply.stdout
            }
            for (family in listOf("-4", "-6")) {
                val ipv6 = family == "-6"
                val all = query(listOf("ip", family, "rule", "show")) ?: return null
                val selected = query(listOf("ip", family, "rule", "show", "table", table)) ?: return null
                val routes = query(listOf("ip", family, "route", "show", "table", table)) ?: return null
                if (!rules(plan, ipv6, all, selected) || !routes(plan, ipv6, attached, routes)) return null
            }
            return result
        }
    }
}
