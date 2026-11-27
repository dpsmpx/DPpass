package com.dpsmpx.dppass.app

/** A completed synchronous helper transaction is required before accepting
 * the descriptor. The receipt identifies the peer and private TUN but
 * does not prove platform safety, link configuration or traffic isolation. */
internal object RootHotspotTunLaunch {
    data class Command(val session: RootHotspotAdmission.Session, val script: String)
    data class Receipt(val identity: RootHotspotTunLifetime.Identity, val helperPid: Int) {
        init { require(helperPid > 1 && identity.name == "dpgateway") }
    }

    private val part = Regex("[A-Za-z0-9_.-]+")
    private fun socketPathValid(path: String): Boolean =
        path.startsWith("/") && path.length in 2..107 &&
            path.drop(1).split('/').all { it.matches(part) && it !in setOf(".", "..") }

    private fun quote(value: String): String = "'" + value.replace("'", "'\\''") + "'"

    /** Executed only inside an exact live bound claim. Stage must come from
     * signed APK assets; install re-verifies its digest in private ROOT storage.
     * The listener is already bound in app-private storage before this call.
     * No child is detached and no network settings are changed. */
    fun script(directory: String, socketPath: String, appUid: Int, appPid: Int,
               source: String, digest: String): String {
        require(socketPathValid(socketPath))
        require(appUid >= 10_000 && appPid > 1)
        require(source.startsWith("/") && source.none { it == '\u0000' || it == '\r' || it == '\n' })
        val helper = quote("$directory/root-pidfd")
        return listOf(
            "(",
            RootPidfdInstall.script(directory, source, digest),
            ") >/dev/null || exit 1",
            RootPidfdCleanup.helperAdmission(helper),
            "$helper probe >/dev/null || exit 1",
            "$helper tun-send " + quote(socketPath) + " $appUid $appPid || exit 1",
        ).joinToString("\n")
    }

    fun parse(session: RootHotspotAdmission.Session, raw: String): Receipt? {
        if (raw.length !in 13..64 || !raw.endsWith('\n')) return null
        val fields = raw.dropLast(1).split(' ')
        if (fields.size != 3 || fields[0] != "tun_sent") return null
        val pid = fields[1].toIntOrNull() ?: return null
        val index = fields[2].toIntOrNull() ?: return null
        if (pid <= 1 || index <= 0 || index == session.downstreamIndex ||
            pid.toString() != fields[1] || index.toString() != fields[2]) return null
        return Receipt(RootHotspotTunLifetime.Identity(session, "dpgateway", index), pid)
    }
}
