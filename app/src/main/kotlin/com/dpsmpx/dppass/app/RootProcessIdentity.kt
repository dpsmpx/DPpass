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

    fun stopExecutable(pidFile: String, executable: String): String =
        withPid(pidFile, "if test \"\$(readlink /proc/\$pid/exe 2>/dev/null)\" = " +
            quote(executable) + "; then kill \"\$pid\" 2>/dev/null || true; fi") +
            "; rm -f " + quote(pidFile)

    fun stopScript(pidFile: String, script: String): String =
        withPid(pidFile, "if tr '\\000' '\\n' </proc/\$pid/cmdline 2>/dev/null | grep -Fxq " +
            quote(script) + "; then kill \"\$pid\" 2>/dev/null || true; fi") +
            "; rm -f " + quote(pidFile)
}
