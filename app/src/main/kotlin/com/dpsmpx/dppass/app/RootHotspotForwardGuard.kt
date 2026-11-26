package com.dpsmpx.dppass.app

/** D-120: разрешает только пару клиентский интерфейс — приватный TUN. */
internal class RootHotspotForwardGuard(downstream: String, tun: String, generation: String) {
    init {
        val name = Regex("[a-zA-Z0-9_][a-zA-Z0-9_-]{0,14}")
        require(downstream.matches(name) && tun.matches(name))
        require(downstream != tun && downstream != "lo" && tun != "lo")
        require(generation.matches(Regex("[a-f0-9]{16}")))
    }

    private val marker = "-m comment --comment dppass-hotspot-$generation"
    private val drops = listOf("-i $downstream", "-o $downstream")
    private val allowed = listOf("-i $downstream -o $tun", "-i $tun -o $downstream")

    // Устанавливать до допуска клиента; IPv6 не открывается ни в одной фазе.
    val install = listOf("iptables", "ip6tables").flatMap { tool ->
        drops.map { "$tool -t filter -I FORWARD 1 $it $marker -j DROP" }
    }
    // Только после проверки принадлежности TUN и допуска сессии.
    val attach = allowed.map { "iptables -t filter -I FORWARD 1 $it $marker -j ACCEPT" }
    val detach = allowed.map { "iptables -t filter -D FORWARD $it $marker -j ACCEPT" }
    val retireAfterAccessPointStopped = listOf("iptables", "ip6tables").flatMap { tool ->
        drops.map { "$tool -t filter -D FORWARD $it $marker -j DROP" }
    }
}
