package com.dpsmpx.dppass.app

/**
 * Preliminary checks of legacy ROOT adapters. These do not install rules,
 * start daemons or prove availability of individual kernel targets.
 * Only call the script after the user has explicitly chosen ROOT.
 */
internal object RootDpiPreflight {
    enum class Kind { SOCKET, PACKET }

    // The side-by-side experimental debug app shares the old adapters'
    // fixed root paths and firewall identifiers. It must not use them.
    fun permitsLegacyRoot(packageId: String): Boolean =
        packageId != "com.dpsmpx.dppass.alpine.localdpi"

    fun script(kind: Kind): String {
        val table = when (kind) {
            Kind.SOCKET -> "nat"
            Kind.PACKET -> "mangle"
        }
        return listOf(
            "set -eu",
            "test \"\$(id -u)\" = 0 || { echo 'su: effective uid is not root'; exit 1; }",
            "command -v iptables >/dev/null || { echo 'iptables unavailable'; exit 1; }",
            "iptables -t $table -S OUTPUT >/dev/null || { echo 'iptables $table OUTPUT unavailable'; exit 1; }",
        ).joinToString("\n")
    }
}
