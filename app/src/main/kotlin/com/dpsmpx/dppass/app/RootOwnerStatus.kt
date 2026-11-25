package com.dpsmpx.dppass.app

/**
 * Read-only classification of persisted ownership. A missing/unreadable
 * proc entry is UNKNOWN, not proof of process death. Never execute record
 * contents as shell commands. The caller must hold the lifecycle lock.
 */
internal object RootOwnerStatus {
    private fun quote(raw: String): String = "'" + raw.replace("'", "'\\''") + "'"

    fun inspect(directory: String, procRoot: String = "/proc"): String = listOf(
        "(",
        "set +e",
        "set -f",
        "unknown() { echo 'ROOT: owner identity unknown'; exit 0; }",
        "valid_boot() { printf '%s\\n' \"\$1\" | grep -Eq '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\$'; }",
        "generation=\$(cat " + quote("$directory/generation") + " 2>/dev/null) || unknown",
        "case \"\$generation\" in ''|*[!a-zA-Z0-9-]*) unknown ;; esac",
        "record=\$(cat " + quote("$directory/owner.identity") + " 2>/dev/null) || unknown",
        "set -- \$record; test \"\$#\" -eq 4 || unknown",
        "test \"\$1\" = \"\$generation\" || unknown",
        "pid=\$2; ticks=\$3; saved_boot=\$4",
        "case \"\$pid\" in ''|*[!0-9]*) unknown ;; esac",
        "case \"\$ticks\" in ''|*[!0-9]*) unknown ;; esac",
        "test \"\$pid\" -gt 1 2>/dev/null && test \"\$pid\" -le 2147483647 2>/dev/null || unknown",
        "valid_boot \"\$saved_boot\" || unknown",
        "current_boot=\$(cat " + quote("$procRoot/sys/kernel/random/boot_id") + " 2>/dev/null) || unknown",
        "valid_boot \"\$current_boot\" || unknown",
        "if test \"\$saved_boot\" != \"\$current_boot\"; then echo 'ROOT: owner identity stale (boot changed)'; exit 0; fi",
        "stat=\$(cat " + quote(procRoot) + "/\$pid/stat 2>/dev/null) || unknown",
        "case \"\$stat\" in \"\$pid (\"*) ;; *) unknown ;; esac",
        "rest=\${stat##*) }; test \"\$rest\" != \"\$stat\" || unknown",
        "set -- \$rest; test \"\$#\" -ge 20 || unknown",
        "case \"\${20}\" in ''|*[!0-9]*) unknown ;; esac",
        "if test \"\${20}\" = \"\$ticks\"; then echo 'ROOT: owner identity matches'; " +
            "else echo 'ROOT: owner identity stale (PID reused)'; fi",
        ")",
    ).joinToString("\n")
}
