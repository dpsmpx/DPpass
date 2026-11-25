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
    private fun migrationStartup(body: String): String {
        if (lockDirectory == directory) return body
        val legacy = "$directory/lifecycle.lock"
        return listOf(
            "dppass_migration_body() {\n$body\n}",
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

    private fun peerAdmissionCheck(): String {
        val peer = peerDirectory ?: return ":"
        // Older adapters did not publish a generation. An outstanding PID
        // record may be stale, but absence of a generation does not prove
        // cleanup. Leave reconciliation to the adapter that owns the files.
        fun absent(name: String): String {
            val path = quote("$peer/$name")
            return "test ! -e $path && test ! -L $path"
        }
        val noPidRecords = listOf("pid", "pid6", "watch.pid").joinToString(" && ") { absent(it) }
        // A confirmed reboot invalidates prior-boot process ownership.
        // Validate all remaining PID records before deleting any. Do not
        // signal processes, touch firewall rules, or attempt same-boot recovery.
        return listOf(
            "if ! ( " + absent("generation") + " ); then",
            "if " + RootOwnerStatus.previousBoot(peer, procRoot) + " && " +
                previousBootPidRecordsSafe(peer) + "; then",
            "rm -f " + listOf("pid", "pid6", "watch.pid").joinToString(" ") { quote("$peer/$it") } + " || exit 1",
            "rm -f " + quote("$peer/owner.identity") + " || exit 1",
            "rm -f " + quote("$peer/generation") + " || exit 1",
            "echo 'ROOT: retired previous-boot owner metadata'",
            "else",
            "echo 'ROOT: other adapter cleanup pending or active'",
            RootOwnerStatus.inspect(peer, procRoot),
            "exit 1",
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

    // Publish a data-only record tied to the generation under the same lock.
    // An unavailable boot ID is explicitly unknown; it is not proof of death.
    private fun publishOwner(owner: RootOwnerIdentity?): String {
        if (owner == null) return ":"
        val temporary = "$ownerRecord.$generation.tmp"
        return listOf(
            "boot_id=\$(cat /proc/sys/kernel/random/boot_id 2>/dev/null) || boot_id=unknown",
            "test -n \"\$boot_id\" || boot_id=unknown",
            "printf '%s %s %s %s\\n' " + quote(generation) + " " + quote(owner.pid.toString()) +
                " " + quote(owner.startTime) + " \"\$boot_id\" > " + quote(temporary),
            "mv -f " + quote(temporary) + " " + quote(ownerRecord),
        ).joinToString("\n")
    }

    fun start(cleanup: String, launch: String, owner: RootOwnerIdentity? = null): String {
        val temporary = "$record.$generation.tmp"
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
                    metadataCheck(record, ownerRecord, temporary, "$ownerRecord.$generation.tmp"),
                    "printf '%s\\n' " + quote(generation) + " > " + quote(temporary),
                    "mv -f " + quote(temporary) + " " + quote(record),
                    publishOwner(owner),
                    // Cleanup may set shell options or exit explicitly.
                    "(\n$cleanup\n) || exit 1",
                    launch,
                ).joinToString("\n")),
            ).joinToString("\n")),
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
            "test -e " + quote(record) + " || exit 0",
            "current=\$(cat " + quote(record) + ") || exit 1",
            "test \"\$current\" = " + quote(generation) + " || exit 0",
            metadataCheck(ownerRecord),
            // A healthy owner must not be cleaned based on a stale probe.
            condition?.let { "if (\n$it\n); then exit 75; fi" } ?: ":",
            "(\n$cleanup\n) || exit 1",
            // A watchdog cannot stop itself in its cleanup body. Retire its
            // PID record only after successful cleanup, before releasing
            // generation ownership. A failed removal remains retryable.
            if (condition != null) "rm -f " + quote("$directory/watch.pid") + " || exit 1" else ":",
            "rm -f " + quote(ownerRecord) + " || exit 1",
            "rm -f " + quote(record) + " || exit 1",
        ).joinToString("\n")),
    ).joinToString("\n")

    fun alive(check: String): String = transaction(
        RootProcessIdentity.generationMatches(record, generation) + " && (\n$check\n)",
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
