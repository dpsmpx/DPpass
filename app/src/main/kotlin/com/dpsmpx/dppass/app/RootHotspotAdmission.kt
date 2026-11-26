package com.dpsmpx.dppass.app

/** D-120: допуск пересылки не следует из одного успешного preflight. */
internal object RootHotspotAdmission {
    enum class Mode { VPN, LOCAL_STRATEGIES }
    enum class Refusal { ROOT_BASELINE, ACCESS_POINT, OFFLOAD, GUARD, EGRESS, DNS, IPV6 }

    /** Привязка подтверждений к одному экземпляру AP и маршрута, а не к имени интерфейса. */
    data class Session(val generation: Long, val downstreamIndex: Int, val mode: Mode) {
        init {
            require(generation > 0 && downstreamIndex > 0)
        }
    }

    data class Evidence(
        val rootBaseline: Boolean,
        val ownedLocalOnlyWifi: Session?,
        val noOffloadBypass: Session?,
        val defaultDenyGuard: Session?,
        val verifiedEgress: Session?,
        val confinedDns: Session?,
        val blockedIpv6: Session?,
    )

    /** IPv4-only этап: неизвестные, чужие и устаревшие подтверждения не разрешают пересылку. */
    fun refusal(request: Session, evidence: Evidence): Refusal? = when {
        !evidence.rootBaseline -> Refusal.ROOT_BASELINE
        evidence.ownedLocalOnlyWifi != request -> Refusal.ACCESS_POINT
        evidence.noOffloadBypass != request -> Refusal.OFFLOAD
        evidence.defaultDenyGuard != request -> Refusal.GUARD
        evidence.verifiedEgress != request -> Refusal.EGRESS
        evidence.confinedDns != request -> Refusal.DNS
        evidence.blockedIpv6 != request -> Refusal.IPV6
        else -> null
    }
}
