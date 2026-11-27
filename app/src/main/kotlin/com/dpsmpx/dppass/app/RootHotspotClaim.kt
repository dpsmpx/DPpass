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
internal class RootHotspotClaim private constructor(
    private val data: RootHotspotOwnerRecord,
    private val lockDirectory: String,
    private val waitSeconds: Int,
    adapterDirectories: List<String>,
    private val procRoot: String,
) {
    constructor(
        session: RootHotspotAdmission.Session,
        lockDirectory: String = RootLifecycleTransaction.SHARED_LOCK_DIRECTORY,
        token: UUID = UUID.randomUUID(),
        waitSeconds: Int = 5,
        adapterDirectories: List<String> = listOf(
            RootLifecycleTransaction.ZAPRET_DIRECTORY, RootLifecycleTransaction.BYEDPI_DIRECTORY,
        ),
        owner: RootHotspotOwner,
        networkSlot: RootHotspotNetworkSlot,
        procRoot: String = "/proc",
    ) : this(RootHotspotOwnerRecord(session, token, owner, networkSlot),
        lockDirectory, waitSeconds, adapterDirectories, procRoot)

    private val owner = data.owner
    private val networkSlot = data.networkSlot
    private val marker = RootHotspotInterlock.marker(lockDirectory)
    private val adapters = adapterDirectories.toList()
    private val lock = "$lockDirectory/lifecycle.lock"
    private val record = data.line()
    private val networkEvidence = RootHotspotCleanupEvidence(networkSlot.table, networkSlot.priority)

    init {
        require(lockDirectory.startsWith("/") && lockDirectory != "/" && !lockDirectory.endsWith("/"))
        require('\u0000' !in lockDirectory && '\n' !in lockDirectory && '\r' !in lockDirectory)
        require(waitSeconds in 1..10)
        require(procRoot.startsWith("/") && procRoot.none { it == '\u0000' || it == '\n' || it == '\r' })
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

    private fun currentBoot(): String = listOf(
        "current_boot=\$(cat " + quote("$procRoot/sys/kernel/random/boot_id") + ") || exit 1",
        "printf '%s\\n' \"\$current_boot\" | grep -Eq '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\$' || exit 1",
    ).joinToString("\n")

    private fun liveOwner(): String = currentBoot() + "\n" +
        "test \"\$current_boot\" = " + quote(owner.bootId.toString()) + " || exit 1\n" +
        RootProcessIdentity.appAlive(owner.identity.pid, owner.identity.startTime, procRoot) + " || exit 1"

    /** Previous boot, or positive same-boot kernel identity proof. No signal. */
    private fun orphanProof(helperPath: String?): String {
        val sameBoot = if (helperPath == null) "exit 1" else {
            val helper = quote(helperPath)
            RootPidfdCleanup.helperAdmission(helper) + "\n" +
                "$helper gone " + owner.identity.pid + " " + quote(owner.identity.startTime) + " " +
                quote(owner.bootId.toString()) + " >/dev/null || exit 1"
        }
        return currentBoot() + "\nif test \"\$current_boot\" = " +
            quote(owner.bootId.toString()) + "; then\n" + sameBoot + "\nfi"
    }

    /** Requires an initialized shared ROOT directory. Never overwrite a claim,
     * including a partial claim after a crash. Failed/ambiguous is not a grant. */
    fun acquire(): String = transaction(listOf(
        absent() + " || exit 1",
        RootHotspotInterlock.adaptersIdle(adapters),
        liveOwner(),
        networkEvidence.script(),
        "set -C",
        "printf '%s\\n' " + quote(record) + " > " + quote(marker),
        matches(),
    ).joinToString("\n"))

    /** Only an unbound record for this exact request may enter the controller. */
    fun pendingFor(request: RootHotspotLifecycle.Request): Boolean =
        data.session == null && data.generation == request.generation && data.mode == request.mode

    /** Read-only exact live-owner check, including an unbound claim.
     * A failed command is not proof that the record is absent. */
    fun confirm(): String = transaction(matches() + "\n" + liveOwner())

    /** Prepare a synchronous, exact-owner helper launch. App PID comes
     * only from the claim, never from a free-form command argument. */
    fun tunLaunch(socketPath: String, appUid: Int, source: String, digest: String): RootHotspotTunLaunch.Command {
        val session = checkNotNull(data.session) { "ROOT hotspot interface not bound" }
        val body = RootHotspotTunLaunch.script(lockDirectory, socketPath, appUid,
            owner.identity.pid, source, digest)
        return RootHotspotTunLaunch.Command(session,
            transaction(matches() + "\n" + liveOwner() + "\n" + body + "\n" + matches() + "\n" + liveOwner()))
    }

    /** A stale owner cannot enter a privileged transaction. */
    fun owned(body: String): String {
        check(data.session != null) { "ROOT hotspot interface not bound" }
        return transaction(matches() + "\n" + liveOwner() + "\n(\n$body\n)")
    }

    data class Binding(val script: String, val claim: RootHotspotClaim)

    /**
     * Caller supplies positively discovered AP identity. Replace the pending
     * record atomically under the lock; the old handle cannot mutate or retire
     * the bound claim. A failed/ambiguous command must be reconciled by inspect,
     * not by repeating AP creation. No forwarding is installed here.
     */
    fun bind(session: RootHotspotAdmission.Session): Binding {
        check(data.session == null) { "ROOT hotspot already bound" }
        require(session.generation == data.generation && session.mode == data.mode)
        val next = RootHotspotClaim(data.copy(downstreamIndex = session.downstreamIndex),
            lockDirectory, waitSeconds, adapters, procRoot)
        val script = transaction(listOf(
            matches(), liveOwner(), RootHotspotInterlock.adaptersIdle(adapters),
            networkEvidence.script(),
            "tmp=\$(mktemp " + quote("$lockDirectory/.hotspot.owner.XXXXXX") + ") || exit 1",
            "trap 'rm -f \"\$tmp\"' EXIT",
            "printf '%s\\n' " + quote(next.record) + " > \"\$tmp\" || exit 1",
            matches(), liveOwner(),
            "mv -f \"\$tmp\" " + quote(marker) + " || exit 1",
            next.matches(),
        ).joinToString("\n"))
        return Binding(script, next)
    }

    /** Caller must supply independent positive proof of full shutdown.
     * Failure retains the claim; no generic force-release is provided.
     * The check and unlink share the lock with cooperating claim operations. */
    fun releaseAfter(verifiedCleanup: String): String = retireAfter(liveOwner(), verifiedCleanup)

    /** Read-only orphan admission; recovery must repeat this under lock. */
    fun confirmOrphan(helperPath: String? = null): String =
        transaction(matches() + "\n" + orphanProof(helperPath))

    /** Recovery requires the exact observed record and fresh positive orphan proof.
     * The trusted cleanup body must prove AP/request retirement and all owned
     * rules/routes/egress cleanup. A prior boot alone does not prove this. */
    fun recoverAfter(verifiedCleanup: String, helperPath: String? = null): String =
        retireAfter(orphanProof(helperPath), verifiedCleanup)

    private fun retireAfter(proof: String, verifiedCleanup: String): String = transaction(listOf(
        matches(),
        proof,
        RootHotspotInterlock.adaptersIdle(adapters),
        "(\n$verifiedCleanup\n) || exit 1",
        networkEvidence.script(),
        RootHotspotInterlock.adaptersIdle(adapters),
        matches(),
        proof,
        "rm " + quote(marker) + " || exit 1",
        absent() + " || exit 1",
    ).joinToString("\n"))

    companion object {
        /** Reconstruct only from an exact parsed record. Recovery still checks
         * current ownership and orphan proof under the lock. */
        fun fromRecord(
            record: RootHotspotOwnerRecord,
            lockDirectory: String = RootLifecycleTransaction.SHARED_LOCK_DIRECTORY,
            adapterDirectories: List<String> = listOf(
                RootLifecycleTransaction.ZAPRET_DIRECTORY, RootLifecycleTransaction.BYEDPI_DIRECTORY,
            ),
            procRoot: String = "/proc",
        ): RootHotspotClaim = RootHotspotClaim(record, lockDirectory, 5, adapterDirectories, procRoot)

        /** Reserve before requesting AP; no invented interface index. */
        fun pending(
            generation: Long,
            mode: RootHotspotAdmission.Mode,
            owner: RootHotspotOwner,
            networkSlot: RootHotspotNetworkSlot,
            lockDirectory: String = RootLifecycleTransaction.SHARED_LOCK_DIRECTORY,
            token: UUID = UUID.randomUUID(),
            adapterDirectories: List<String> = listOf(
                RootLifecycleTransaction.ZAPRET_DIRECTORY, RootLifecycleTransaction.BYEDPI_DIRECTORY,
            ),
            procRoot: String = "/proc",
        ): RootHotspotClaim = fromRecord(
            RootHotspotOwnerRecord(generation, mode, null, token, owner, networkSlot),
            lockDirectory, adapterDirectories, procRoot,
        )

        /** Distinguish an absent record from an unreadable/malformed one.
         * This is an observation only; never use it as a grant to start. */
        fun inspectState(lockDirectory: String = RootLifecycleTransaction.SHARED_LOCK_DIRECTORY): String {
            val file = "'" + RootHotspotInterlock.marker(lockDirectory).replace("'", "'\\''") + "'"
            return RootProcessIdentity.lockedTransaction("$lockDirectory/lifecycle.lock", listOf(
                "set -eu",
                "if test ! -e $file && test ! -L $file; then",
                "    printf 'absent\\n'; exit 0",
                "fi",
                "test -f $file && test ! -L $file || exit 1",
                "test \"\$(stat -c %u $file)\" = \"\$(id -u)\" || exit 1",
                "test \"\$(wc -c < $file)\" -le 256 || exit 1",
                "printf 'present\\n'",
                "cat $file",
            ).joinToString("\n"))
        }

        /** Read under lock; caller must parse the complete successful stdout.
         * Inspection never grants ownership; recovery rechecks the exact record. */
        fun inspect(lockDirectory: String = RootLifecycleTransaction.SHARED_LOCK_DIRECTORY): String {
            val file = "'" + RootHotspotInterlock.marker(lockDirectory).replace("'", "'\\''") + "'"
            return RootProcessIdentity.lockedTransaction("$lockDirectory/lifecycle.lock", listOf(
                "set -eu",
                "test -f $file && test ! -L $file || exit 1",
                "test \"\$(stat -c %u $file)\" = \"\$(id -u)\" || exit 1",
                "test \"\$(wc -c < $file)\" -le 256 || exit 1",
                "cat $file",
            ).joinToString("\n"))
        }
    }
}
