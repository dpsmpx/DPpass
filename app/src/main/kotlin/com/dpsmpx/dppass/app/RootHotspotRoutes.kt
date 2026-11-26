package com.dpsmpx.dppass.app

/** D-120: порядок изоляции IP-маршрутов. Не открывает AP или пересылку сам. */
internal class RootHotspotRoutes(downstream: String, tun: String, table: Int, priority: Int) {
    init {
        val name = Regex("[a-zA-Z0-9_][a-zA-Z0-9_-]{0,14}")
        require(downstream.matches(name) && tun.matches(name))
        require(downstream != tun && downstream != "lo" && tun != "lo")
        require(table in 10_000..20_000 && priority in 100..999)
    }

    // Читать под блокировкой шлюза перед установкой. Используем вывод всех
    // таблиц: запрос отсутствующей таблицы на разных ядрах имеет разный статус.
    val checkVacant = """
        (
        set -eu
        for family in -4 -6; do
            rules=${'$'}(ip "${'$'}family" rule show) || exit 1
            routes=${'$'}(ip "${'$'}family" route show table all) || exit 1
            printf '%s\n' "${'$'}rules" | awk -v p=$priority -v t=$table '
                ${'$'}1 == p ":" || ${'$'}1 == (p+1) ":" { busy=1 }
                { for (i=1; i<NF; i++) if (${'$'}i == "lookup" && ${'$'}(i+1) == t) busy=1 }
                END { exit busy }
            ' || exit 1
            printf '%s\n' "${'$'}routes" | awk -v t=$table '
                { for (i=1; i<NF; i++) if (${'$'}i == "table" && ${'$'}(i+1) == t) busy=1 }
                END { exit busy }
            ' || exit 1
        done
        )
    """.trimIndent()

    // Эта проверка не резервирует ресурсы у Android/netd. Владение
    // интерфейсом, INPUT и отсутствие обхода через offload проверяются отдельно.
    val guard = listOf(
        "ip -4 rule add iif $downstream priority ${priority + 1} unreachable",
        "ip -6 rule add iif $downstream priority ${priority + 1} unreachable",
        "ip -4 route add unreachable default metric 32767 table $table",
        "ip -4 rule add iif $downstream priority $priority lookup $table",
    )
    val attach = "ip -4 route add default dev $tun metric 100 table $table"
    val detach = "ip -4 route del default dev $tun metric 100 table $table"

    // Только после подтверждённой остановки AP. Пока клиент может передавать
    // пакеты, терминальные правила должны остаться даже после detach.
    val retireAfterAccessPointStopped = listOf(
        "ip -4 rule del iif $downstream priority $priority lookup $table",
        "ip -4 route del unreachable default metric 32767 table $table",
        "ip -6 rule del iif $downstream priority ${priority + 1} unreachable",
        "ip -4 rule del iif $downstream priority ${priority + 1} unreachable",
    )
}
