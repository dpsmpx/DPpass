package com.dpsmpx.dppass.app

/** The same exact-rule and process cleanup is used for stop and recovery. */
internal object RootAdapterCleanup {
    const val BYEDPI_RULE = "-p tcp -m owner ! --uid-owner 0 -m addrtype ! --dst-type LOCAL -m multiport --dports 80,443 -m comment --comment dppass-byedpi -j REDIRECT --to-ports 40529"
    const val ZAPRET_TCP = "-p tcp -m mark ! --mark 0x40000000/0x40000000 -m multiport --dports 80,443 -j NFQUEUE --queue-num 20529 --queue-bypass"
    const val ZAPRET_UDP = "-p udp -m mark ! --mark 0x40000000/0x40000000 --dport 443 -j NFQUEUE --queue-num 20529 --queue-bypass"

    fun byeDpi(stopWatch: Boolean = true): String {
        val root = RootLifecycleTransaction.BYEDPI_DIRECTORY
        return script(root, RootFirewallCleanup.Kind.SOCKET, listOf(BYEDPI_RULE),
            "watch.sh", "ciadpi", listOf("pid", "pid6"), stopWatch)
    }

    fun zapret2(stopWatch: Boolean = true): String {
        val root = RootLifecycleTransaction.ZAPRET_DIRECTORY
        return script(root, RootFirewallCleanup.Kind.PACKET, listOf(ZAPRET_TCP, ZAPRET_UDP),
            "watchdog.sh", "nfqws2", listOf("pid"), stopWatch)
    }

    private fun script(root: String, kind: RootFirewallCleanup.Kind, rules: List<String>,
                       watchdog: String, executable: String, names: List<String>, stopWatch: Boolean): String =
        buildString {
            appendLine("set +e")
            appendLine(RootFirewallCleanup.remove(kind, "iptables", rules))
            appendLine(RootFirewallCleanup.remove(kind, "ip6tables", rules,
                optional = true, intentFile = "$root/ipv6.intent"))
            if (stopWatch) appendLine(RootPidfdCleanup.stopWatchdog(root, "$root/$watchdog"))
            for (name in names) appendLine(RootPidfdCleanup.stopExecutable(root, name, "$root/$executable"))
            appendLine("exit 0")
        }
}
