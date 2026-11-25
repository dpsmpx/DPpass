package com.dpsmpx.dppass.app

/**
 * Shared cleanup guard for legacy ROOT adapters. PID files alone are not
 * process identity: a stale or reused PID may belong to an unrelated app.
 * The executable/script check reduces this risk; it is not an atomic pidfd
 * check, so physical ROOT lifecycle verification is still required.
 */
internal object RootProcessIdentity {
    private fun quote(raw: String): String = "'" + raw.replace("'", "'\\''") + "'"

    // The caller supplies only fixed root-owned paths, never user input.
    private fun withPid(file: String, action: String): String =
        "if test -s " + quote(file) + "; then " +
            "pid=\$(cat " + quote(file) + " 2>/dev/null); " +
            "case \"\$pid\" in ''|*[!0-9]*) ;; *) " +
            "if test \"\$pid\" -gt 1 2>/dev/null; then " +
            action + "; fi ;; esac; fi"

    // A subshell isolates the validated PID from the caller. Missing,
    // malformed, stale or unrelated process identities all fail closed.
    fun executableAlive(pidFile: String, executable: String): String =
        "( test -s " + quote(pidFile) + " || exit 1; " +
            "pid=\$(cat " + quote(pidFile) + " 2>/dev/null) || exit 1; " +
            "case \"\$pid\" in ''|*[!0-9]*) exit 1 ;; esac; " +
            "test \"\$pid\" -gt 1 2>/dev/null || exit 1; " +
            "test \"\$(readlink /proc/\$pid/exe 2>/dev/null)\" = " + quote(executable) +
            " && kill -0 \"\$pid\" 2>/dev/null )"

    /** Watchdog and foreground health checks must agree on daemon identity.
     * An optional daemon is absent only when its PID file is absent.
     */
    fun optionalExecutableAlive(pidFile: String, executable: String): String =
        "( ! test -e " + quote(pidFile) + " || " + executableAlive(pidFile, executable) + " )"

    /** Linux proc stat field 22, after the final command-name delimiter. */
    fun startTime(stat: String): String? {
        val suffix = stat.substringAfterLast(") ", "").trim()
        if (suffix.isEmpty()) return null
        return suffix.split(Regex("\\s+")).getOrNull(19)
            ?.takeIf { it.isNotEmpty() && it.all { ch -> ch in '0'..'9' } }
    }

    fun currentAppStartTime(): String =
        startTime(java.io.File("/proc/self/stat").readText())
            ?: error("ROOT: app process start time unavailable")

    fun appAlive(appPid: Int, appStartTime: String): String {
        require(appPid > 1 && appStartTime.isNotEmpty() && appStartTime.all { it in '0'..'9' })
        // Disable globbing before splitting the stat suffix in a subshell.
        return "( set -f; stat=\$(cat /proc/$appPid/stat 2>/dev/null) || exit 1; " +
            "rest=\${stat##*) }; test \"\$rest\" != \"\$stat\" || exit 1; " +
            "set -- \$rest; test \"\$#\" -ge 20 && test \"\${20}\" = " +
            quote(appStartTime) + " && kill -0 $appPid 2>/dev/null )"
    }

    fun watchdogCondition(appPid: Int, appStartTime: String, pidFile: String, executable: String,
                          optionalPidFile: String? = null): String {
        return appAlive(appPid, appStartTime) + " && " + executableAlive(pidFile, executable) +
            (optionalPidFile?.let { " && " + optionalExecutableAlive(it, executable) } ?: "")
    }

    fun stopExecutable(pidFile: String, executable: String): String =
        withPid(pidFile, "if test \"\$(readlink /proc/\$pid/exe 2>/dev/null)\" = " +
            quote(executable) + "; then kill \"\$pid\" 2>/dev/null || true; fi") +
            "; rm -f " + quote(pidFile)

    fun stopScript(pidFile: String, script: String): String =
        withPid(pidFile, "if tr '\\000' '\\n' </proc/\$pid/cmdline 2>/dev/null | grep -Fxq " +
            quote(script) + "; then kill \"\$pid\" 2>/dev/null || true; fi") +
            "; rm -f " + quote(pidFile)

    /**
     * A bounded shell transaction on an existing private, root-owned directory.
     * Never unlink the lock file: waiters must refer to the same inode.
     * Callers must close fd 9 in long-lived children (including watchdogs).
     * Missing flock, an unavailable lock or an open failure must fail closed.
     */
    fun lockedTransaction(lockFile: String, body: String, waitSeconds: Int = 5): String {
        require(waitSeconds in 1..10)
        return listOf(
            "(",
            "umask 077",
            "command -v flock >/dev/null 2>&1 || { echo 'ROOT: flock unavailable'; exit 1; }",
            "exec 9>>" + quote(lockFile) + " || exit 1",
            "flock -x -w $waitSeconds 9 || { echo 'ROOT: lifecycle lock unavailable'; exit 1; }",
            body,
            ")",
        ).joinToString("\n")
    }

/** A long-lived child must not inherit the lifecycle lock descriptor.
     * Preserve the child PID ($!) and keep all standard streams detached.
     * The command is already shell-quoted by the caller.
     */
    fun detachedCommand(command: String, logFile: String): String =
        command + " </dev/null > " + quote(logFile) + " 2>&1 9>&- &"

    /** Only the matching launch generation may perform deferred cleanup.
     * Use this check INSIDE lockedTransaction, not before acquiring the lock.
     */
    fun generationMatches(generationFile: String, generation: String): String {
        require(generation.isNotEmpty() && generation.all { it in 'a'..'z' || it in 'A'..'Z' || it in '0'..'9' || it == '-' })
        return "test \"\$(cat " + quote(generationFile) + " 2>/dev/null)\" = " + quote(generation)
    }
}
