package com.dpsmpx.dppass.app

/** Strict cleanup of an identified ROOT child under the lifecycle lock. */
internal object RootPidfdCleanup {
    private fun quote(raw: String) = "'" + raw.replace("'", "'\\''") + "'"
    private fun regularOrAbsent(file: String) =
        "( test ! -L $file && { test ! -e $file || test -f $file; } )"

    fun requireForLaunch(directory: String): String {
        val helper = quote("$directory/root-pidfd")
        val marker = quote("$directory/pidfd.required")
        return listOf(
            "test -f $helper && test ! -L $helper && test -x $helper || exit 1",
            "$helper probe || { echo 'ROOT: pidfd not available'; exit 1; }",
            regularOrAbsent(marker) + " || exit 1",
            "printf '%s\\n' v1 > $marker || exit 1",
        ).joinToString("\n")
    }

    fun stopExecutable(directory: String, name: String, executable: String): String {
        require(name in listOf("pid", "pid6"))
        return stop(directory, name, "stop-executable", quote(executable),
            RootProcessIdentity.stopExecutable("$directory/$name", executable))
    }

    fun stopWatchdog(directory: String, script: String): String =
        stop(directory, "watch.pid", "stop-script", "\"\$interpreter\" " + quote(script),
            RootProcessIdentity.stopScript("$directory/watch.pid", script), watchdog = true)

    private fun stop(directory: String, name: String, mode: String, arguments: String,
                     legacy: String, watchdog: Boolean = false): String {
        val pidFile = quote("$directory/$name")
        val identity = quote("$directory/$name.identity")
        val marker = quote("$directory/pidfd.required")
        val helper = quote("$directory/root-pidfd")
        return listOf(
            "(", "set -f",
            regularOrAbsent(pidFile) + " && " + regularOrAbsent(identity) + " && " +
                regularOrAbsent(marker) + " || exit 1",
            "if test -e $marker; then test \"\$(cat $marker)\" = v1 || exit 1; fi",
            "if ! test -e $pidFile && ! test -e $identity; then exit 0; fi",
            "paired=0",
            "if test -e $pidFile; then",
            "pid=\$(cat $pidFile) || exit 1",
            "case \"\$pid\" in ''|0*|*[!0-9]*) exit 1 ;; esac",
            "test \"\$pid\" -gt 1 2>/dev/null && test \"\$pid\" -le 2147483647 2>/dev/null || exit 1",
            "paired=1",
            "else",
            // An unpaired identity is evidence of a potentially live task.
            // It may be retired only by a no-signal native gone proof.
            "pid=",
            "fi",
            // Preserve non-Alpine behavior only if no helper was installed
            // and this session never required one. Never fall back from
            // a failed native operation or a missing recorded identity.
            "if test \"\$paired\" = 1 && ! test -e $marker && ! test -e $helper && ! test -L $helper; then",
            legacy,
            "exit 0",
            "fi",
            "test -f $helper && test ! -L $helper && test -x $helper || exit 1",
            "test \"\$(stat -c %u $helper)\" = \"\$(id -u)\" || exit 1",
            "test \"\$( $helper --version )\" = dppass-root-pidfd/1 || exit 1",
            // Missing sidecar after a crash/upgrade: do not invent start
            // ticks from a live process. Only a positive kernel absence
            // or death proof permits retirement, with no signal at all.
            "if ! test -e $identity; then",
            "test \"\$paired\" = 1 || exit 1",
            "current_boot=\$(cat /proc/sys/kernel/random/boot_id) || exit 1",
            "$helper absent \"\$pid\" \"\$current_boot\" >/dev/null || { echo 'ROOT: child identity missing and PID not proven gone'; exit 1; }",
            "test \"\$(cat $pidFile)\" = \"\$pid\" || exit 1",
            "rm -f $pidFile || exit 1",
            "exit 0",
            "fi",
            "current=\$( " + RootOwnerStatus.generation(directory) + " ) || exit 1",
            "raw=\$(cat $identity) || exit 1",
            "set -- \$raw; test \"\$#\" -eq 5 && test \"\$1\" = v1 || exit 1",
            "test \"\$2\" = \"\$current\" || exit 1",
            "if test \"\$paired\" = 1; then test \"\$3\" = \"\$pid\" || exit 1; else pid=\$3; fi",
            "case \"\$pid\" in ''|0*|*[!0-9]*) exit 1 ;; esac",
            "test \"\$pid\" -gt 1 2>/dev/null && test \"\$pid\" -le 2147483647 2>/dev/null || exit 1",
            "ticks=\$4; boot=\$5",
            "case \"\$ticks\" in ''|*[!0-9]*) exit 1 ;; esac",
            "printf '%s\\n' \"\$boot\" | grep -Eq '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\$' || exit 1",
            "if test \"\$paired\" = 0; then",
            "$helper gone \"\$pid\" \"\$ticks\" \"\$boot\" >/dev/null || { echo 'ROOT: unpaired child not proven gone'; exit 1; }",
            "test ! -e $pidFile && test ! -L $pidFile || exit 1",
            "test \"\$(cat $identity)\" = \"\$raw\" || exit 1",
            "exit 0",
            "fi",
            "if ! $helper gone \"\$pid\" \"\$ticks\" \"\$boot\" >/dev/null; then",
            if (watchdog) "interpreter=\$(readlink -f /system/bin/sh) || exit 1" else ":",
            "$helper $mode \"\$pid\" \"\$ticks\" \"\$boot\" $arguments 2000 || exit 1",
            "fi",
            "test \"\$(cat $pidFile)\" = \"\$pid\" || exit 1",
            "test \"\$(cat $identity)\" = \"\$raw\" || exit 1",
            "rm -f $pidFile || exit 1",
            ") || exit 1",
        ).joinToString("\n")
    }
}
