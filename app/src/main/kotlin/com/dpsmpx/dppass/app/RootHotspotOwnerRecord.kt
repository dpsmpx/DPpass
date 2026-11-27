package com.dpsmpx.dppass.app

import java.util.UUID

internal data class RootHotspotOwner(val identity: RootOwnerIdentity, val bootId: UUID) {
    init {
        require(identity.startTime.length <= 20)
        require(identity.startTime == "0" || !identity.startTime.startsWith("0"))
    }
}

/** Exactly the resources reserved by this session; also persisted for recovery. */
internal data class RootHotspotNetworkSlot(val table: Int, val priority: Int) {
    init {
        require(table in 10_000..20_000 && priority in 100..999)
    }
}

/** Canonical, bounded V3 record. Older experimental records fail closed. */
internal data class RootHotspotOwnerRecord(
    val session: RootHotspotAdmission.Session,
    val token: UUID,
    val owner: RootHotspotOwner,
    val networkSlot: RootHotspotNetworkSlot,
) {
    fun line(): String = listOf("v3", token, session.generation, session.downstreamIndex,
        session.mode.name, owner.identity.pid, owner.identity.startTime, owner.bootId,
        networkSlot.table, networkSlot.priority).joinToString(" ")

    companion object {
        fun parse(raw: String): RootHotspotOwnerRecord? {
            if (raw.length > 256 || !raw.endsWith("\n")) return null
            val parts = raw.dropLast(1).split(' ')
            if (parts.size != 10 || parts[0] != "v3") return null
            return try {
                val record = RootHotspotOwnerRecord(
                    RootHotspotAdmission.Session(parts[2].toLong(), parts[3].toInt(),
                        RootHotspotAdmission.Mode.valueOf(parts[4])),
                    UUID.fromString(parts[1]),
                    RootHotspotOwner(RootOwnerIdentity(parts[5].toInt(), parts[6]), UUID.fromString(parts[7])),
                    RootHotspotNetworkSlot(parts[8].toInt(), parts[9].toInt()),
                )
                record.takeIf { it.line() + "\n" == raw }
            } catch (_: IllegalArgumentException) {
                null
            }
        }
    }
}
