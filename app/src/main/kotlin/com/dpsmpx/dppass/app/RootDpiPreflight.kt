package com.dpsmpx.dppass.app

import com.dpsmpx.dppass.connection.Zapret2Backend

/**
 * Admission to the existing ROOT adapters, not proof of individual kernel
 * targets or of successful packet execution. Never acquires ROOT unless the
 * service has already been started with an explicitly selected ROOT backend.
 */
internal object RootDpiPreflight {
    enum class Kind { SOCKET, PACKET }

    data class Admission(val kind: Kind, val ipv6Output: Boolean)

    // The side-by-side experimental debug app shares the old adapters'
    // fixed root paths and firewall identifiers. It must not use them.
    fun permitsLegacyRoot(packageId: String): Boolean =
        packageId != "com.dpsmpx.dppass.alpine.localdpi"

    fun kind(backend: Zapret2Backend): Kind? = when (backend) {
        Zapret2Backend.BYEDPI_ROOT -> Kind.SOCKET
        Zapret2Backend.ROOT -> Kind.PACKET
        else -> null
    }

    /** Required IPv4 prerequisites. IPv6 remains independently optional in
     * the legacy adapters; missing IPv6 tables do not authorize IPv6 rules.
     * Raw access is required for the packet adapter, not for TCP sockets.
     */
    fun refusal(kind: Kind, report: RootCapabilitySurvey.Report?): String? = when {
        report == null -> "ROOT: не удалось подтвердить эффективные привилегии"
        !report.netAdmin -> "ROOT: требуется CAP_NET_ADMIN"
        kind == Kind.PACKET && !report.netRaw -> "ROOT: требуется CAP_NET_RAW"
        kind == Kind.SOCKET && !report.ipv4Nat -> "ROOT: недоступна IPv4 NAT OUTPUT"
        kind == Kind.PACKET && !report.ipv4Mangle -> "ROOT: недоступна IPv4 mangle OUTPUT"
        else -> null
    }

    /** Fresh read-only survey before staging or privileged rule changes.
     * A failed probe cannot be replaced by a cached UI result or another
     * executor. The launch still checks its actual rules and processes.
     */
    fun requireReady(
        kind: Kind,
        survey: () -> RootCapabilitySurvey.Report? = { RootCapabilitySurvey.run() },
    ): Admission {
        val report = survey()
        refusal(kind, report)?.let { error(it) }
        checkNotNull(report)
        val ipv6Output = when (kind) {
            Kind.SOCKET -> report.ipv6Nat
            Kind.PACKET -> report.ipv6Mangle
        }
        return Admission(kind, ipv6Output)
    }
}
