package com.dpsmpx.dppass.app

import java.util.UUID

internal data class RootHotspotOwner(val identity: RootOwnerIdentity, val bootId: UUID) {
    init {
        require(identity.startTime.length <= 20)
        require(identity.startTime == "0" || !identity.startTime.startsWith("0"))
    }
}

/** Canonical, bounded V2 record. No compatibility path for experimental V1. */
internal data class RootHotspotOwnerRecord(
    val session: RootHotspotAdmission.Session,
    val token: UUID,
    val owner: RootHotspotOwner,
) {
    fun line(): String = listOf("v2", token, session.generation, session.downstreamIndex,
        session.mode.name, owner.identity.pid, owner.identity.startTime, owner.bootId).joinToString(" ")

    companion object {
        fun parse(raw: String): RootHotspotOwnerRecord? {
            if (raw.length > 256 || !raw.endsWith("\n")) return null
            val parts = raw.dropLast(1).split(' ')
            if (parts.size != 8 || parts[0] != "v2") return null
            return try {
                val record = RootHotspotOwnerRecord(
                    RootHotspotAdmission.Session(parts[2].toLong(), parts[3].toInt(),
                        RootHotspotAdmission.Mode.valueOf(parts[4])),
                    UUID.fromString(parts[1]),
                    RootHotspotOwner(RootOwnerIdentity(parts[5].toInt(), parts[6]), UUID.fromString(parts[7])),
                )
                record.takeIf { it.line() + "\n" == raw }
            } catch (_: IllegalArgumentException) {
                null
            }
        }
    }
}
