package com.dpsmpx.dppass.app

import java.util.UUID

/**
 * D-120: persistent experimental hotspot claim under the existing ROOT flock.
 * A flock serializes a transaction, not the AP lifetime. The claim survives
 * process exit and prevents another cooperating hotspot owner from starting.
 * Never infer recovery from a missing process.
 * Only trusted internal shell bodies may be supplied. Current ROOT adapters
 * share the lock; external tethering tools and old builds do not participate.
 */
internal class RootHotspotClaim(
    session: RootHotspotAdmission.Session,
    private val lockDirectory: String = RootLifecycleTransaction.SHARED_LOCK_DIRECTORY,
    token: UUID = UUID.randomUUID(),
    private val waitSeconds: Int = 5,
    adapterDirectories: List<String> = listOf(
        RootLifecycleTransaction.ZAPRET_DIRECTORY, RootLifecycleTransaction.BYEDPI_DIRECTORY,
    ),
) {
    private val marker = RootHotspotInterlock.marker(lockDirectory)
    private val adapters = adapterDirectories.toList()
    private val lock = "$lockDirectory/lifecycle.lock"
    private val record = listOf("v1", token, session.generation, session.downstreamIndex, session.mode.name).joinToString(" ")

    init {
        require(lockDirectory.startsWith("/") && lockDirectory != "/" && !lockDirectory.endsWith("/"))
        require('\u0000' !in lockDirectory && '\n' !in lockDirectory && '\r' !in lockDirectory)
        require(waitSeconds in 1..10)
        require(adapters.distinct().size == adapters.size && lockDirectory !in adapters)
        adapters.forEach { require(it.startsWith("/") && it != "/" && !it.endsWith("/"))
            require(it.none { c -> c == '\u0000' || c == '\n' || c == '\r' }) }
    }

    private fun quote(value: String): String = "'" + value.replace("'", "'\\''") + "'"

    private fun transaction(body: String): String = RootProcessIdentity.lockedTransaction(
        lock, "set -eu\n" + body, waitSeconds,
    )

    private fun absent(): String {
        val file = quote(marker)
        return "test ! -e $file && test ! -L $file"
    }

    private fun matches(): String {
        val file = quote(marker)
        return listOf(
            "test -f $file && test ! -L $file || exit 1",
            "test \"\$(stat -c %u $file)\" = \"\$(id -u)\" || exit 1",
            "test \"\$(wc -c < $file)\" -eq " + (record.length + 1) + " || exit 1",
            "test \"\$(cat $file)\" = " + quote(record) + " || exit 1",
        ).joinToString("\n")
    }

    /** Requires an initialized shared ROOT directory. Never overwrite a claim,
     * including a partial claim after a crash. Failed/ambiguous is not a grant. */
    fun acquire(): String = transaction(listOf(
        absent() + " || exit 1",
        RootHotspotInterlock.adaptersIdle(adapters),
        "set -C",
        "printf '%s\\n' " + quote(record) + " > " + quote(marker),
        matches(),
    ).joinToString("\n"))

    /** A stale owner cannot enter a privileged transaction. */
    fun owned(body: String): String = transaction(matches() + "\n(\n$body\n)")

    /** Caller must supply independent positive proof of full shutdown.
     * Failure retains the claim; no generic force-release is provided.
     * The check and unlink share the lock with cooperating claim operations. */
    fun releaseAfter(verifiedCleanup: String): String = transaction(listOf(
        matches(),
        "(\n$verifiedCleanup\n) || exit 1",
        matches(),
        "rm " + quote(marker) + " || exit 1",
        absent() + " || exit 1",
    ).joinToString("\n"))
}
