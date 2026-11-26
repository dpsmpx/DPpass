package com.dpsmpx.dppass.app

/** D-120: план для подтверждённого интерфейса AP. Не управляет точкой доступа. */
internal class RootHotspotInputGuard(downstream: String, generation: String) {
    init {
        require(downstream.matches(Regex("[a-zA-Z0-9_][a-zA-Z0-9_-]{0,14}")) && downstream != "lo")
        require(generation.matches(Regex("[a-f0-9]{16}")))
    }

    private val client = "-i $downstream -m comment --comment dppass-hotspot-$generation"
    private val dhcp = "$client -p udp --sport 68 --dport 67 -j ACCEPT"
    private val block = "$client -j DROP"

    // Установить и сверить весь план до допуска клиентов. DNS телефона не открыт.
    val install = listOf(
        "iptables -t filter -I INPUT 1 $block",
        "ip6tables -t filter -I INPUT 1 $block",
        "iptables -t filter -I INPUT 1 $dhcp",
    )

    // Только после подтверждённой остановки AP. Удаляем точные правила с меткой сессии.
    val retireAfterAccessPointStopped = listOf(
        "iptables -t filter -D INPUT $dhcp",
        "ip6tables -t filter -D INPUT $block",
        "iptables -t filter -D INPUT $block",
    )
}
