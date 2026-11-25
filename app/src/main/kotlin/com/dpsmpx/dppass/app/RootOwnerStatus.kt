package com.dpsmpx.dppass.app

/**
 * Read-only classification of persisted ownership. A missing/unreadable
 * proc entry is UNKNOWN, not proof of process death. Never execute record
 * contents as shell commands. The caller must hold the lifecycle lock.
 */
internal object RootOwnerStatus {
    private fun quote(raw: String): String = "'" + raw.replace("'", "'\\''") + "'"

    private enum class Proof { DIAGNOSTIC, PREVIOUS_BOOT, SAME_BOOT_ORPHAN }

    fun inspect(directory: String, procRoot: String = "/proc"): String =
        probe(directory, procRoot, Proof.DIAGNOSTIC)

    /** Success only for a validated generation and a different, valid boot ID. */
    fun previousBoot(directory: String, procRoot: String = "/proc"): String =
        probe(directory, procRoot, Proof.PREVIOUS_BOOT) + " >/dev/null"

    /** Positive proof only: a V2 owner on this boot has a reused PID or is
     * a verified zombie/dead task. Missing proc data is never proof.
     * This does not establish daemon identity or authorize signaling it.
     */
    fun sameBootOrphaned(directory: String, procRoot: String = "/proc"): String =
        probe(directory, procRoot, Proof.SAME_BOOT_ORPHAN) + " >/dev/null"

    /** Strict recovery also covers an owner already reaped by the kernel. */
    fun sameBootOrphanedWithPidfd(directory: String, procRoot: String = "/proc"): String =
        probe(directory, procRoot, Proof.SAME_BOOT_ORPHAN, "$directory/root-pidfd") + " >/dev/null"

    // The generation file is the commit point. V2 stores the complete
    // identity there; legacy records use a separate owner.identity file.
    private fun readGeneration(directory: String, fail: String): String = listOf(
        "test -f " + quote("$directory/generation") + " && test ! -L " + quote("$directory/generation") + " || $fail",
        "raw=\$(cat " + quote("$directory/generation") + " 2>/dev/null) || $fail",
        "set -- \$raw",
        "identity=",
        "if test \"\$#\" -eq 1 && test \"\$raw\" = \"\$1\"; then",
        "generation=\$1",
        "elif test \"\$#\" -eq 5 && test \"\$1\" = v2; then",
        "generation=\$2; identity=\"\$2 \$3 \$4 \$5\"",
        "else $fail; fi",
        "case \"\$generation\" in ''|*[!a-zA-Z0-9-]*) $fail ;; esac",
    ).joinToString("\n")

    private fun validBoot(): String =
        "valid_boot() { printf '%s\\n' \"\$1\" | grep -Eq '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\$'; }"

    // Legacy sidecars may remain after a successful V2 commit. They are
    // no longer authoritative, but nonregular entries still block cleanup.
    private fun readIdentity(directory: String, fail: String, allowLegacyMissing: Boolean): String {
        val owner = quote("$directory/owner.identity")
        return listOf(
            "test ! -L $owner && { test ! -e $owner || test -f $owner; } || $fail",
            "if test -z \"\$identity\"; then",
            if (allowLegacyMissing) "if test ! -e $owner; then " +
                "test ! -e $owner.\$generation.tmp && test ! -L $owner.\$generation.tmp || $fail; exit 0; fi" else ":",
            "identity=\$(cat $owner 2>/dev/null) || $fail",
            "fi",
            "set -- \$identity; test \"\$#\" -eq 4 || $fail",
            "test \"\$1\" = \"\$generation\" || $fail",
            "pid=\$2; ticks=\$3; saved_boot=\$4",
            "case \"\$pid\" in ''|0*|*[!0-9]*) $fail ;; esac",
            "case \"\$ticks\" in ''|*[!0-9]*) $fail ;; esac",
            "test \"\$pid\" -gt 1 2>/dev/null && test \"\$pid\" -le 2147483647 2>/dev/null || $fail",
            "test \"\$saved_boot\" = unknown || valid_boot \"\$saved_boot\" || $fail",
        ).joinToString("\n")
    }

    fun generation(directory: String): String = listOf(
        "(", "set -f", readGeneration(directory, "exit 1"), "printf '%s\\n' \"\$generation\"", ")",
    ).joinToString("\n")

    /** Match a currently initiating app instance, never just its numeric PID. */
    fun ownedBy(directory: String, owner: RootOwnerIdentity, procRoot: String = "/proc"): String = listOf(
        "(", "set -f", validBoot(), readGeneration(directory, "exit 1"),
        "test -n \"\$identity\" || exit 1",
        readIdentity(directory, "exit 1", allowLegacyMissing = false),
        "valid_boot \"\$saved_boot\" || exit 1",
        "current_boot=\$(cat " + quote("$procRoot/sys/kernel/random/boot_id") + " 2>/dev/null) || exit 1",
        "test \"\$saved_boot\" = \"\$current_boot\" || exit 1",
        "test \"\$pid\" = " + quote(owner.pid.toString()) + " && test \"\$ticks\" = " + quote(owner.startTime),
        ")",
    ).joinToString("\n")

    fun consistent(directory: String): String = listOf(
        "(", "set -f", validBoot(), readGeneration(directory, "exit 1"),
        readIdentity(directory, "exit 1", allowLegacyMissing = true), ")",
    ).joinToString("\n")

    private fun probe(directory: String, procRoot: String, proof: Proof, nativeHelper: String? = null): String = listOf(
        "(",
        "set +e",
        "set -f",
        "unknown() { echo 'ROOT: owner identity unknown'; exit " +
            (if (proof == Proof.DIAGNOSTIC) "0" else "1") + "; }",
        validBoot(),
        readGeneration(directory, "unknown"),
        // Do not authorize same-boot recovery from older split records.
        if (proof == Proof.SAME_BOOT_ORPHAN) "test -n \"\$identity\" || unknown" else ":",
        readIdentity(directory, "unknown", allowLegacyMissing = false),
        "valid_boot \"\$saved_boot\" || unknown",
        "current_boot=\$(cat " + quote("$procRoot/sys/kernel/random/boot_id") + " 2>/dev/null) || unknown",
        "valid_boot \"\$current_boot\" || unknown",
        "if test \"\$saved_boot\" != \"\$current_boot\"; then echo 'ROOT: owner identity stale (boot changed)'; exit " +
            (if (proof == Proof.SAME_BOOT_ORPHAN) "1" else "0") + "; fi",
        if (proof == Proof.PREVIOUS_BOOT) "exit 1" else ":",
        if (nativeHelper != null) {
            val helper = quote(nativeHelper)
            "test -f $helper && test ! -L $helper && test -x $helper || unknown\n" +
                "test \"\$(stat -c %u $helper)\" = \"\$(id -u)\" || unknown\n" +
                "test \"\$( $helper --version )\" = dppass-root-pidfd/1 || unknown\n" +
                "if $helper gone \"\$pid\" \"\$ticks\" \"\$saved_boot\"; then exit 0; else unknown; fi"
        } else ":",
        "stat=\$(cat " + quote(procRoot) + "/\$pid/stat 2>/dev/null) || unknown",
        "case \"\$stat\" in \"\$pid (\"*) ;; *) unknown ;; esac",
        "rest=\${stat##*) }; test \"\$rest\" != \"\$stat\" || unknown",
        "set -- \$rest; test \"\$#\" -ge 20 || unknown",
        "case \"\${20}\" in ''|*[!0-9]*) unknown ;; esac",
        // A matching start time is not evidence of a running process when
        // proc still exposes a zombie or dead task. Unknown states stay unknown.
        "case \"\$1\" in R|S|D|T|t|I|W|P|Z|X|x) ;; *) unknown ;; esac",
        "if test \"\${20}\" != \"\$ticks\"; then echo 'ROOT: owner identity stale (PID reused)'; " +
            "elif test \"\$1\" = Z || test \"\$1\" = X || test \"\$1\" = x; then " +
            "echo 'ROOT: owner identity terminated (dead task)'; " +
            "else echo 'ROOT: owner identity matches'; exit " +
            (if (proof == Proof.SAME_BOOT_ORPHAN) "1" else "0") + "; fi",
        ")",
    ).joinToString("\n")
}
