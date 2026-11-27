package com.dpsmpx.dppass.app

/** Only the exact descriptor-owned, nonpersistent TUN may be configured.
 * Caller must hold the bound claim and have independently verified guards.
 * External ROOT/netd writers are not serialized by this claim. */
internal class RootHotspotTunSetup(
    private val identity: RootHotspotTunLifetime.Identity,
    private val mtu: Int,
) {
    init { require(identity.name == "dpgateway" && mtu in 576..1500) }
    private val sys = "/sys/class/net/dpgateway"
    private val ipv6 = "/proc/sys/net/ipv6/conf/dpgateway/disable_ipv6"

    private fun exact(): String = listOf(
        "test \"\$(cat $sys/ifindex)\" = '${identity.index}' || exit 1",
        "test \"\$(cat $sys/type)\" = 65534 || exit 1",
        "test \"\$(cat $sys/tun_flags)\" = 0x1001 || exit 1",
    ).joinToString("\n")

    private fun noAddresses(): String = listOf(
        "addr4=\$(ip -4 -o addr show dev dpgateway) || exit 1",
        "test -z \"\$addr4\" || exit 1",
        "addr6=\$(ip -6 -o addr show dev dpgateway) || exit 1",
        "test -z \"\$addr6\" || exit 1",
    ).joinToString("\n")

    private fun link(up: Boolean): String = listOf(
        "link=\$(ip -o link show dev dpgateway) || exit 1",
        "printf '%s\\n' \"\$link\" | awk -v idx='${identity.index}:' '" +
            "\$1 == idx && \$2 == \"dpgateway:\" && \$3 ~ /^<[^>]*>\$/ " +
            "{ flags=\$3; gsub(/[<>]/,\"\",flags); n=split(flags,a,\",\"); for(i=1;i<=n;i++) if(a[i]==\"UP\") count++; rows++; next } " +
            "{ bad=1 } END { exit (bad || rows != 1 || count != " + (if (up) 1 else 0) + ") }' || exit 1",
    ).joinToString("\n")

    /** Read-only postconditions; repeat identity after observations. */
    fun verify(): String = listOf(
        exact(),
        "test \"\$(cat $sys/mtu)\" = '$mtu' || exit 1",
        "test \"\$(cat $ipv6)\" = 1 || exit 1",
        link(true), noAddresses(), exact(),
    ).joinToString("\n")

    /** No global sysctl, routes, addresses or firewall changes. */
    fun configure(): String = listOf(
        exact(), noAddresses(), link(false), exact(),
        "printf '1\\n' > $ipv6 || exit 1",
        "test \"\$(cat $ipv6)\" = 1 || exit 1",
        exact(),
        "ip link set dev dpgateway mtu $mtu up || exit 1",
        verify(),
    ).joinToString("\n")
}
