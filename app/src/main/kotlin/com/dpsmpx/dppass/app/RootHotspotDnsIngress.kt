package com.dpsmpx.dppass.app

import com.dpsmpx.dppass.engine.xray.XrayBackend

/** D-120: DNS, который DHCP направил самому шлюзу, передаётся виртуальному DNS ядра. */
internal class RootHotspotDnsIngress(downstream: String, gateway: String, generation: String) {
    init {
        require(downstream.matches(Regex("[a-zA-Z0-9_][a-zA-Z0-9_-]{0,14}")) && downstream != "lo")
        val octets = gateway.split('.').map { it.toIntOrNull()?.takeIf { value -> value in 0..255 && value.toString() == it } }
        require(octets.size == 4 && octets.all { it != null })
        require(octets[0] == 10 || (octets[0] == 172 && octets[1] in 16..31) || (octets[0] == 192 && octets[1] == 168))
        require(generation.matches(Regex("[a-f0-9]{16}")))
    }

    private val rules = listOf("udp", "tcp").map { proto ->
        "-i $downstream -d $gateway/32 -p $proto --dport 53 -m comment --comment dppass-hotspot-$generation " +
            "-j DNAT --to-destination ${XrayBackend.TUN_DNS4}:53"
    }
    val attach = rules.map { "iptables -t nat -I PREROUTING 1 $it" }
    val detach = rules.map { "iptables -t nat -D PREROUTING $it" }
}
