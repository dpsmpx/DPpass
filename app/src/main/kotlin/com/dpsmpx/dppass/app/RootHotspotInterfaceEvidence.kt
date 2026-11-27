package com.dpsmpx.dppass.app

/**
 * D-120: narrow, fail-closed interpretation of complete successful
 * 'ip -o link show' and 'ip -4 -o addr show' inventories. Callers must supply
 * full output (never RootCommandRunner's log tail), check command exit codes,
 * and take fresh observations under the session's platform/ROOT ownership.
 * The two commands are not an atomic kernel snapshot.
 */
internal object RootHotspotInterfaceEvidence {
    private const val MAX_OUTPUT = 256 * 1024
    private val name = Regex("[a-zA-Z0-9_][a-zA-Z0-9_-]{0,14}")
    private val linkRow = Regex("""([1-9][0-9]*): ([^ :]+): .+""")
    private val addressRow = Regex("""([1-9][0-9]*):\s+(\S+)\s+inet\s+(\S+)(?:\s+.*)?""")

    class Inventory internal constructor(
        private val links: Map<String, Int>,
        private val addresses: Map<String, Set<String>>,
    ) {
        fun sameTopology(other: Inventory): Boolean = links == other.links && addresses == other.addresses
        fun indexOf(name: String): Int? = links[name]
        fun nameOf(index: Int): String? = links.entries.firstOrNull { it.value == index }?.key
        fun ipv4(name: String): Set<String> = addresses[name].orEmpty()
        fun interfacesWith(address: String): Set<String> =
            addresses.filterValues { address in it }.keys
    }

    data class Identity(val session: RootHotspotAdmission.Session, val name: String, val gateway: String)

    /** Only a platform adapter with positive evidence may provide INACTIVE or ABSENT. */
    enum class PlatformState { LOCAL_ONLY, INACTIVE, ABSENT, OTHER, UNKNOWN }

    data class StopObservation(
        val session: RootHotspotAdmission.Session,
        val requestRetired: Boolean,
        val platformState: PlatformState,
        val inventory: Inventory?,
    )

    private fun interfaceName(raw: String): String? {
        val parts = raw.split('@')
        if (parts.size > 2 || !parts[0].matches(name)) return null
        if (parts.size == 2 && !parts[1].matches(name)) return null
        return parts[0]
    }

    private fun octets(raw: String): List<Int>? {
        val parts = raw.split('.')
        if (parts.size != 4) return null
        return parts.map { part ->
            val n = part.toIntOrNull() ?: return null
            if (n !in 0..255 || n.toString() != part) return null
            n
        }
    }

    private fun privateGateway(raw: String): Boolean {
        val ip = octets(raw) ?: return false
        return ip[0] == 10 || (ip[0] == 172 && ip[1] in 16..31) || (ip[0] == 192 && ip[1] == 168)
    }

    private fun rows(raw: String): List<String>? {
        if (raw.length > MAX_OUTPUT || raw.any { it == '\u0000' || it == '\r' }) return null
        return raw.trimEnd('\n').split('\n').takeIf { rows -> rows.none { it.isBlank() } }
    }

    /** Null means unusable evidence, not an empty inventory. */
    fun parse(linkOutput: String?, ipv4Output: String?): Inventory? {
        val linkRows = rows(linkOutput ?: return null) ?: return null
        val addrRows = rows(ipv4Output ?: return null) ?: return null
        val links = mutableMapOf<String, Int>()
        val indices = mutableSetOf<Int>()
        for (row in linkRows) {
            val match = linkRow.matchEntire(row) ?: return null
            val index = match.groupValues[1].toIntOrNull() ?: return null
            val iface = interfaceName(match.groupValues[2]) ?: return null
            if (links.put(iface, index) != null || !indices.add(index)) return null
        }
        val addresses = mutableMapOf<String, MutableSet<String>>()
        for (row in addrRows) {
            val match = addressRow.matchEntire(row) ?: return null
            val index = match.groupValues[1].toIntOrNull() ?: return null
            val iface = interfaceName(match.groupValues[2]) ?: return null
            if (links[iface] != index) return null
            val cidr = match.groupValues[3].split('/')
            if (cidr.size != 2 || octets(cidr[0]) == null) return null
            val prefix = cidr[1].toIntOrNull() ?: return null
            if (prefix !in 0..32 || prefix.toString() != cidr[1]) return null
            addresses.getOrPut(iface) { mutableSetOf() }.add(cidr[0])
        }
        // Missing loopback is a common sign of filtered/truncated output.
        if ("lo" !in links || "127.0.0.1" !in addresses["lo"].orEmpty()) return null
        return Inventory(links.toMap(), addresses.mapValues { it.value.toSet() })
    }

    /** Require a sole positively identified local-only AP and an unambiguous private gateway. */
    fun discover(
        session: RootHotspotAdmission.Session,
        inventory: Inventory?,
        localOnlyInterfaces: Set<String>,
        gateway: String,
    ): Identity? {
        if (inventory == null || !privateGateway(gateway)) return null
        val iface = localOnlyInterfaces.singleOrNull() ?: return null
        if (iface == "lo" || !iface.matches(name)) return null
        if (inventory.indexOf(iface) != session.downstreamIndex) return null
        if (inventory.interfacesWith(gateway) != setOf(iface)) return null
        return Identity(session, iface, gateway)
    }

    /**
     * Guard retirement is conservative: both name and index absent, or the
     * exact retained interface is positively inactive with no IPv4 addresses.
     * Name/index reuse, a migrated gateway, and unknown platform state refuse.
     */
    fun stopped(identity: Identity, observed: StopObservation): Boolean {
        if (identity.session != observed.session || !observed.requestRetired) return false
        if (!identity.name.matches(name) || identity.name == "lo" || !privateGateway(identity.gateway)) return false
        val inventory = observed.inventory ?: return false
        if (inventory.interfacesWith(identity.gateway).isNotEmpty()) return false
        val index = inventory.indexOf(identity.name)
        val iface = inventory.nameOf(identity.session.downstreamIndex)
        return when (observed.platformState) {
            PlatformState.ABSENT -> index == null && iface == null
            PlatformState.INACTIVE ->
                index == identity.session.downstreamIndex && iface == identity.name &&
                    inventory.ipv4(identity.name).isEmpty()
            else -> false
        }
    }
}
