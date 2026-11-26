package com.dpsmpx.dppass.app

/** D-120: порядок изоляции IP-маршрутов. Не открывает AP или пересылку сам. */
internal class RootHotspotRoutes(downstream: String, tun: String, table: Int, priority: Int) {
    init {
        val name = Regex("[a-zA-Z0-9_][a-zA-Z0-9_-]{0,14}")
        require(downstream.matches(name) && tun.matches(name))
        require(downstream != tun && downstream != "lo" && tun != "lo")
        require(table in 10_000..20_000 && priority in 100..999)
    }

    // Вызывающий обязан проверить эксклюзивное владение таблицей, приоритетами
    // и интерфейсом. INPUT и обход через offload проверяются отдельно.
    val guard = listOf(
        "ip -4 rule add iif $downstream priority ${priority + 1} unreachable",
        "ip -6 rule add iif $downstream priority ${priority + 1} unreachable",
        "ip -4 route add unreachable default metric 32767 table $table",
        "ip -4 rule add iif $downstream priority $priority lookup $table",
    )
    val attach = "ip -4 route add default dev $tun metric 100 table $table"
    val detach = "ip -4 route del default dev $tun metric 100 table $table"
}
