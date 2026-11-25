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

    fun watchdogCondition(appPid: Int, pidFile: String, executable: String,
                          optionalPidFile: String? = null): String {
        require(appPid > 1)
        return "kill -0 $appPid 2>/dev/null && " + executableAlive(pidFile, executable) +
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
}
