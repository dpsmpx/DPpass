package com.dpsmpx.dppass.app

/** Host-only shell functions; never query or modify real networking in claim tests. */
internal object RootHotspotNetworkFixture {
    val slot = RootHotspotNetworkSlot(12000, 400)
    val clean = """
        iptables() {
            test "${'$'}1" = -t && test "${'$'}3" = -S || return 91
            printf '%s\n' "-P ${'$'}4 ACCEPT"
        }
        ip6tables() { iptables "${'$'}@"; }
        ip() {
            case "${'$'}*" in
                '-4 rule show'|'-6 rule show') echo '0: from all lookup local';;
                '-4 rule show table 12000'|'-6 rule show table 12000'|'-4 route show table 12000'|'-6 route show table 12000') :;;
                *) return 91;;
            esac
        }
    """.trimIndent() + "\n"

    val dirty = """
        iptables() {
            printf '%s\n' "-P ${'$'}4 ACCEPT" "-A ${'$'}4 -m comment --comment dppass-hotspot-residual -j DROP"
        }
    """.trimIndent() + "\n"
}
