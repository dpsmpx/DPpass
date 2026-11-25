package com.dpsmpx.dppass.app

import java.util.UUID

/** PID and Linux start ticks identify an application instance, not just a PID. */
internal data class RootOwnerIdentity(val pid: Int, val startTime: String) {
    init {
        require(pid > 1 && startTime.isNotEmpty() && startTime.all { it in '0'..'9' })
    }
}

/**
 * Lifecycle transaction with an optional shared lock and peer ownership check.
 * The lock inode is stable, and a generation is published before any
 * cleanup or launch. An obsolete adapter/watchdog cannot clean a new one.
 * Old versions that do not honor this lock still require migration tests.
 */
internal class RootLifecycleTransaction(
    private val directory: String,
    private val generation: String = UUID.randomUUID().toString(),
    private val lockDirectory: String = directory,
    private val peerDirectory: String? = null,
    private val procRoot: String = "/proc",
    private val peerCleanup: String? = null,
) {
    private val lock = "$lockDirectory/lifecycle.lock"
    private val record = "$directory/generation"
    private val ownerRecord = "$directory/owner.identity"

    private fun quote(value: String): String = "'" + value.replace("'", "'\\''") + "'"

    init {
        require(peerDirectory != directory)
        // Validate even before rendering a startup script.
        RootProcessIdentity.generationMatches(record, generation)
    }

    private fun transaction(body: String): String =
        RootProcessIdentity.lockedTransaction(lock, body)

    /**
     * The previous generation-aware implementation used a per-adapter lock.
     * During startup, take that lock too if present, always after the shared
     * lock. Do not unlink it or create it on a fresh install. A previous
     * watchdog holding it must finish before we replace the generation.
     */
    private fun migrationStartup(body: String, dir: String = directory): String {
        if (lockDirectory == dir) return body
        val legacy = "$dir/lifecycle.lock"
        return listOf(
            "dppass_migration_body() {\n$body\n}",
            metadataCheck(legacy),
            "if test -e " + quote(legacy) + "; then",
            RootProcessIdentity.lockedTransaction(legacy, "dppass_migration_body", 1),
            "else",
            "dppass_migration_body",
            "fi",
        ).joinToString("\n")
    }

    /**
     * Only use after a positive previous-boot proof. A visible current PID,
     * nonregular file, or malformed record keeps the admission guard closed.
     * This is metadata validation, never a process signal.
     */
    private fun previousBootPidRecordsSafe(peer: String): String {
        val records = listOf("pid", "pid6", "watch.pid").joinToString(" ") { quote("$peer/$it") }
        return listOf(
            "(",
            "for file in $records; do",
            "if test ! -e \"\$file\" && test ! -L \"\$file\"; then continue; fi",
            "test -f \"\$file\" && test ! -L \"\$file\" || exit 1",
            "pid=\$(cat \"\$file\" 2>/dev/null) || exit 1",
            "case \"\$pid\" in ''|0*|*[!0-9]*) exit 1 ;; esac",
            "test \"\$pid\" -gt 1 2>/dev/null && test \"\$pid\" -le 2147483647 2>/dev/null || exit 1",
            "test ! -e " + quote(procRoot) + "/\$pid && test ! -L " + quote(procRoot) + "/\$pid || exit 1",
            "done",
            ")",
        ).joinToString("\n")
    }

    /** Only strict, positively orphaned peers can be reconciled automatically.
     * No fallback to legacy cleanup when owner proof is missing. The caller
     * holds the shared lock; also honor a peer's older per-adapter lock. */
    private fun recoverStrictPeer(peer: String, cleanup: String): String {
        val strict = quote("$peer/pidfd.required")
        val generationFile = quote("$peer/generation")
        val owner = quote("$peer/owner.identity")
        val pids = childPidRecords(peer)
        val absent = (pids + "$peer/ipv6.intent").joinToString(" && ") {
            "test ! -e " + quote(it) + " && test ! -L " + quote(it)
        }
        return migrationStartup(listOf(
            "test -d " + quote(peer) + " && test ! -L " + quote(peer) + " || exit 1",
            metadataCheck("$peer/generation", "$peer/owner.identity", "$peer/pidfd.required",
                "$peer/ipv6.intent", *(pids + childIdentityRecords(peer)).toTypedArray()),
            "test -f $strict && test \"\$(cat $strict)\" = v1 || exit 1",
            RootOwnerStatus.sameBootOrphanedWithPidfd(peer, procRoot) +
                " || { echo 'ROOT: peer orphan ownership unproven'; exit 1; }",
            "(\n$cleanup\n) || exit 1",
            absent + " || { echo 'ROOT: peer cleanup incomplete'; exit 1; }",
            retireChildIdentities(peer),
            "rm -f $owner || exit 1",
            "rm -f $generationFile || exit 1",
            "echo 'ROOT: recovered orphaned strict peer'",
        ).joinToString("\n"), peer)
    }

    // Use the same previous-boot validation for either adapter. No signal
    // is sent to any previous-boot PID, even if the path would match.
    private fun previousBootRecordsSafe(dir: String): String =
        RootOwnerStatus.previousBoot(dir, procRoot) + " && " +
            previousBootPidRecordsSafe(dir) + " && " +
            regularOrAbsent("$dir/ipv6.intent") + " && " + regularOrAbsent("$dir/pidfd.required") + " && " +
            "prior_generation=\$( " + RootOwnerStatus.generation(dir) + " ) && " +
            childPidRecords(dir).joinToString(" && ") {
                RootChildIdentity.previousBootRecordSafe(it, "\"\$prior_generation\"", procRoot)
            }

    private fun retirePreviousBootRecords(dir: String): String =
        "rm -f " + (childPidRecords(dir) + childIdentityRecords(dir) +
            listOf("$dir/ipv6.intent", "$dir/pidfd.required")).joinToString(" ") { quote(it) } + " || exit 1"

    private fun peerAdmissionCheck(): String {
        val peer = peerDirectory ?: return ":"
        // Older adapters did not publish a generation. An outstanding PID
        // record may be stale, but absence of a generation does not prove
        // cleanup. Leave reconciliation to the adapter that owns the files.
        fun absent(name: String): String {
            val path = quote("$peer/$name")
            return "test ! -e $path && test ! -L $path"
        }
        val noPidRecords = (childPidRecords(peer) + childIdentityRecords(peer) + listOf("$peer/ipv6.intent", "$peer/pidfd.required")).joinToString(" && ") { absent(it.substringAfterLast('/')) }
        // A confirmed reboot invalidates prior-boot process ownership.
        // Validate all remaining PID records before deleting any. Do not
        // signal processes, touch firewall rules, or attempt same-boot recovery.
        return listOf(
            "if ! ( " + absent("generation") + " ); then",
            "if " + previousBootRecordsSafe(peer) + "; then",
            retirePreviousBootRecords(peer),
            "rm -f " + quote("$peer/owner.identity") + " || exit 1",
            "rm -f " + quote("$peer/generation") + " || exit 1",
            "echo 'ROOT: retired previous-boot owner metadata'",
            "else",
            if (peerCleanup != null) "(\n" + recoverStrictPeer(peer, peerCleanup) + "\n) || { " +
                "echo 'ROOT: other adapter cleanup pending or active'; exit 1; }"
            else "echo 'ROOT: other adapter cleanup pending or active'\n" +
                RootOwnerStatus.inspect(peer, procRoot) + "\nexit 1",
            "fi",
            "fi",
            absent("owner.identity") +
                " || { echo 'ROOT: unmatched peer owner metadata remains'; exit 1; }",
            noPidRecords +
                " || { echo 'ROOT: previous adapter PID records remain; stop that mode first'; exit 1; }",
        ).joinToString("\n")
    }

    // Reject ambiguous file types before reading or replacing metadata.
    // In particular, mv to an existing directory may return success without
    // replacing the intended record. Never follow a metadata symlink.
    private fun regularOrAbsent(path: String): String {
        val file = quote(path)
        return "( test ! -L $file && { test ! -e $file || test -f $file; } )"
    }

    private fun metadataCheck(vararg paths: String): String =
        paths.joinToString(" && ") { regularOrAbsent(it) } +
            " || { echo 'ROOT: invalid lifecycle metadata file type'; exit 1; }"


    private fun childPidRecords(dir: String = directory): List<String> =
        listOf("pid", "pid6", "watch.pid").map { "$dir/$it" }

    private fun childIdentityRecords(dir: String = directory): List<String> =
        childPidRecords(dir).map { "$it.identity" }

    /** Diagnostic capture only. Failure is visible to the root command log
     * but does not change the legacy adapter's launch/rollback semantics.
     * Retry briefly for the watchdog shell to acquire its script argument.
     */
    private fun captureChild(command: String): String =
        "if ! $command; then sleep 1; " +
            "if ! $command; then echo 'ROOT: child identity unavailable'; " +
            "test ! -e " + quote("$directory/pidfd.required") + " || exit 1; fi; fi"

    fun captureExecutable(name: String, executable: String): String {
        require(name in listOf("pid", "pid6"))
        return captureChild(RootChildIdentity.captureExecutable("$directory/$name", generation, executable, procRoot))
    }

    fun captureWatchdog(script: String): String =
        captureChild(RootChildIdentity.captureScript("$directory/watch.pid", generation, script, procRoot))

    // Validate the entire set before removing any sidecar. In particular,
    // an outstanding IPv6/watchdog PID must not erase the primary evidence.
    // A filesystem failure during unlink remains retryable; this is not
    // an atomic multi-file deletion.
    private fun retireChildIdentities(dir: String = directory): String {
        val identities = childIdentityRecords(dir)
        val checks = childPidRecords(dir).map { pid ->
            val identity = quote("$pid.identity")
            val file = quote(pid)
            "if test -e $identity; then " +
                "test ! -e $file && test ! -L $file " +
                "|| { echo 'ROOT: child PID record remains'; exit 1; }; fi"
        }
        val strictMarker = quote("$dir/pidfd.required")
        val strictCheck = "if test -e $strictMarker; then " +
            childPidRecords(dir).joinToString(" && ") { "test ! -e " + quote(it) + " && test ! -L " + quote(it) } +
            " || exit 1; fi"
        return (listOf(metadataCheck(*identities.toTypedArray(), "$dir/pidfd.required")) + checks + strictCheck +
            ("rm -f " + (identities + "$dir/pidfd.required").joinToString(" ") { quote(it) } + " || exit 1"))
            .joinToString("\n")
    }

    // Stage the entire V2 record in the same directory and publish with
    // one rename. Generation-only fixtures/legacy callers remain supported.
    private fun stageGeneration(temporary: String, owner: RootOwnerIdentity?): String {
        if (owner == null) return "printf '%s\\n' " + quote(generation) + " > " + quote(temporary)
        return listOf(
            "boot_id=\$(cat " + quote("$procRoot/sys/kernel/random/boot_id") + " 2>/dev/null) || boot_id=unknown",
            "printf '%s\\n' \"\$boot_id\" | grep -Eq '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\$' || boot_id=unknown",
            "printf 'v2 %s %s %s %s\\n' " + quote(generation) + " " + quote(owner.pid.toString()) +
                " " + quote(owner.startTime) + " \"\$boot_id\" > " + quote(temporary),
        ).joinToString("\n")
    }

    fun start(cleanup: String, launch: String, owner: RootOwnerIdentity? = null,
              preservePreviousOwner: Boolean = false, prepare: String = ":"): String {
        val temporary = "$record.$generation.tmp"
        val publish = "mv -f " + quote(temporary) + " " + quote(record)
        val cleanupBody = "(\n$cleanup\n) || exit 1"
        val strict = quote("$directory/pidfd.required")
        val ownerCheck = if (owner != null) RootOwnerStatus.ownedBy(directory, owner, procRoot) else "false"
        val reconcilePrevious = listOf(
            "if " + RootOwnerStatus.previousBoot(directory, procRoot) + "; then",
            previousBootRecordsSafe(directory) + " || { echo 'ROOT: previous boot records unproven'; exit 1; }",
            retirePreviousBootRecords(directory),
            "elif test -e $strict || test -L $strict; then",
            "test -f $strict && test ! -L $strict && test \"\$(cat $strict)\" = v1 || exit 1",
            "( $ownerCheck ) || " + RootOwnerStatus.sameBootOrphanedWithPidfd(directory, procRoot) +
                " || { echo 'ROOT: previous strict owner active or unproven'; exit 1; }",
            "fi",
        ).joinToString("\n")
        val handover = if (preservePreviousOwner) listOf(
            "if test -e " + quote(record) + "; then",
            RootOwnerStatus.consistent(directory) + " || { echo 'ROOT: previous owner metadata inconsistent'; exit 1; }",
            reconcilePrevious,
            // Keep the previous generation authoritative until the cleanup
            // callback and all child retirement postconditions succeed.
            cleanupBody,
            retireChildIdentities(),
            publish,
            "else",
            (listOf(ownerRecord, "$directory/pidfd.required") + childIdentityRecords()).joinToString(" && ") {
                "test ! -e " + quote(it) + " && test ! -L " + quote(it)
            } + " || { echo 'ROOT: unmatched owner metadata remains'; exit 1; }",
            publish,
            cleanupBody,
            retireChildIdentities(),
            "fi",
        ).joinToString("\n") else listOf(publish, cleanupBody, retireChildIdentities()).joinToString("\n")
        return listOf(
            "set -eu",
            "umask 077",
            "mkdir -p " + quote(lockDirectory),
            "chmod 700 " + quote(lockDirectory),
            transaction(listOf(
                "set -eu",
                // Refuse a peer with outstanding ownership, even if its
                // watchdog has not yet completed cleanup. Do not clean it here.
                peerAdmissionCheck(),
                "mkdir -p " + quote(directory),
                "chmod 700 " + quote(directory),
                migrationStartup(listOf(
                    metadataCheck(record, ownerRecord, temporary, "$ownerRecord.$generation.tmp", "$directory/pidfd.required",
                        "$directory/ipv6.intent", *childIdentityRecords().toTypedArray()),
                    stageGeneration(temporary, owner),
                    prepare,
                    handover,
                    launch,
                ).joinToString("\n")),
            ).joinToString("\n")),
        ).joinToString("\n")
    }

    /**
     * Explicit recovery transaction for a positively orphaned V2 owner.
     * The caller supplies adapter-specific, idempotent cleanup; this method
     * never signals a process or manipulates firewall rules itself.
     * Not wired to production admission until daemon identity and firewall
     * cleanup postconditions are validated. The proof and cleanup share the
     * same lifecycle (and, where present, previous adapter) lock.
     */
    fun recoverOrphan(cleanup: String): String {
        val pidRecords = listOf("pid", "pid6", "watch.pid").map { "$directory/$it" }
        val absent = pidRecords.joinToString(" && ") {
            "test ! -e " + quote(it) + " && test ! -L " + quote(it)
        }
        return listOf(
            "test -d " + quote(directory) + " || exit 1",
            transaction(migrationStartup(listOf(
                metadataCheck(record, ownerRecord, *(pidRecords + childIdentityRecords()).toTypedArray()),
                RootOwnerStatus.sameBootOrphaned(directory, procRoot) +
                    " || { echo 'ROOT: orphan ownership not proven'; exit 1; }",
                // Validate PID data before handing control to a cleanup
                // implementation. This is not proof of daemon identity.
                "for file in " + pidRecords.joinToString(" ") { quote(it) } + "; do",
                "if test ! -e \"\$file\"; then continue; fi",
                "pid=\$(cat \"\$file\" 2>/dev/null) || exit 1",
                "case \"\$pid\" in ''|0*|*[!0-9]*) exit 1 ;; esac",
                "test \"\$pid\" -gt 1 2>/dev/null && test \"\$pid\" -le 2147483647 2>/dev/null || exit 1",
                "done",
                // A cleanup callback must not return success with remaining
                // PID records. Do not discard the canonical ownership proof.
                "(\n$cleanup\n) || exit 1",
                absent + " || { echo 'ROOT: orphan PID records remain'; exit 1; }",
                retireChildIdentities(),
                "rm -f " + quote(ownerRecord) + " || exit 1",
                "rm -f " + quote(record) + " || exit 1",
            ).joinToString("\n"))),
        ).joinToString("\n")
    }

    fun stop(cleanup: String): String = cleanupTransaction(cleanup)

    /** One watchdog poll. Zero means finished, nonzero means retry.
     * The generation and health checks share the cleanup lock.
     */
    fun watchdogPoll(condition: String, cleanup: String): String =
        cleanupTransaction(cleanup, condition)

    private fun cleanupTransaction(cleanup: String, condition: String? = null): String = listOf(
        // Do not create an absent ROOT directory during a stop.
        "test -d " + quote(directory) + " || exit 0",
        transaction(listOf(
            metadataCheck(record),
            // A missing generation with leftover owner metadata is ambiguous,
            // not proof that cleanup finished. Preserve it for reconciliation.
            "if ! test -e " + quote(record) + "; then",
            (listOf(ownerRecord, "$directory/ipv6.intent", "$directory/pidfd.required") + childIdentityRecords()).joinToString(" && ") {
                "test ! -e " + quote(it) + " && test ! -L " + quote(it)
            } + " || { echo 'ROOT: unmatched owner metadata remains'; exit 1; }",
            "exit 0",
            "fi",
            "current=\$( " + RootOwnerStatus.generation(directory) + " ) || exit 1",
            "test \"\$current\" = " + quote(generation) + " || exit 0",
            metadataCheck(ownerRecord, "$directory/pidfd.required", *childIdentityRecords().toTypedArray()),
            RootOwnerStatus.consistent(directory) + " || { echo 'ROOT: inconsistent owner metadata'; exit 1; }",
            // A healthy owner must not be cleaned based on a stale probe.
            condition?.let { "if (\n$it\n); then exit 75; fi" } ?: ":",
            "(\n$cleanup\n) || exit 1",
            // A watchdog cannot stop itself in its cleanup body. Retire its
            // PID record only after successful cleanup, before releasing
            // generation ownership. A failed removal remains retryable.
            if (condition != null) "rm -f " + quote("$directory/watch.pid") + " || exit 1" else ":",
            retireChildIdentities(),
            "rm -f " + quote(ownerRecord) + " || exit 1",
            "rm -f " + quote(record) + " || exit 1",
        ).joinToString("\n")),
    ).joinToString("\n")

    /** Foreground and watchdog use identical generation-bound child health.
     * Legacy launches without a strict marker retain their old probe.
     * For strict launches, an optional child is absent only if both records
     * are absent; a dangling sidecar or symlink is not healthy. */
    fun executableHealthy(name: String, executable: String, optional: Boolean = false): String {
        require(name in listOf("pid", "pid6"))
        val pidPath = "$directory/$name"
        val pid = quote(pidPath)
        val identity = quote("$pidPath.identity")
        val strict = quote("$directory/pidfd.required")
        val legacy = if (optional) RootProcessIdentity.optionalExecutableAlive(pidPath, executable)
            else RootProcessIdentity.executableAlive(pidPath, executable)
        return listOf(
            "(",
            metadataCheck("$directory/pidfd.required", pidPath, "$pidPath.identity"),
            "if ! test -e $strict; then",
            legacy,
            "exit \$?",
            "fi",
            "test \"\$(cat $strict)\" = v1 || exit 1",
            if (optional) "if test ! -e $pid && test ! -e $identity; then exit 0; fi" else ":",
            RootChildIdentity.matchesExecutable(pidPath, generation, executable, procRoot),
            ")",
        ).joinToString("\n")
    }

    fun alive(check: String): String = transaction(
        metadataCheck(record) + "\n" +
            "current=\$( " + RootOwnerStatus.generation(directory) + " ) && test \"\$current\" = " + quote(generation) + " && " +
            RootOwnerStatus.consistent(directory) + " && (\n$check\n)",
    )

    companion object {
        const val SHARED_LOCK_DIRECTORY = "/data/adb/dppass-root-lifecycle"
        const val ZAPRET_DIRECTORY = "/data/adb/dppass-zapret2"
        const val BYEDPI_DIRECTORY = "/data/adb/dppass-byedpi"
    }

    fun watchdog(condition: String, cleanup: String): String =
        // Healthy, contended or failed cleanup polls retry. A stale or
        // absent generation exits without touching any newer resources.
        "while ! (\n" + watchdogPoll(condition, cleanup) + "\n); do sleep 3; done"
}
