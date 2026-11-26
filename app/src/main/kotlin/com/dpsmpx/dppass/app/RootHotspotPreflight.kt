package com.dpsmpx.dppass.app

/** D-120: инвентаризация без изменения маршрутов, правил и настроек раздачи. */
internal object RootHotspotPreflight {
    fun script(): String = """
        set -eu
        test "${'$'}(id -u)" = 0 || { echo 'root_required'; exit 1; }
        for tool in ip iptables ip6tables; do
            command -v "${'$'}tool" >/dev/null || { echo "missing_${'$'}tool"; exit 1; }
        done
        for tool in iptables ip6tables; do
            "${'$'}tool" -t filter -S FORWARD >/dev/null || { echo "forward_unavailable_${'$'}tool"; exit 1; }
            "${'$'}tool" -t filter -S INPUT >/dev/null || { echo "input_unavailable_${'$'}tool"; exit 1; }
        done
        echo 'baseline_available'
    """.trimIndent()
}
