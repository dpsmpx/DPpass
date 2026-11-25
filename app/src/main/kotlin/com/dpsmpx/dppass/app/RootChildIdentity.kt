package com.dpsmpx.dppass.app

/**
 * Generation-bound child identity for future ROOT recovery. Only capture a
 * freshly launched child under the lifecycle lock; never manufacture identity
 * for an existing legacy PID file. These probes do not signal processes.
 */
internal object RootChildIdentity {
    private fun quote(raw: String): String = "'" + raw.replace("'", "'\\''") + "'"

    private fun validateGeneration(generation: String) {
        require(generation.isNotEmpty() && generation.all {
            it in 'a'..'z' || it in 'A'..'Z' || it in '0'..'9' || it == '-'
        })
    }

    private fun regular(path: String): String =
        "test -f " + quote(path) + " && test ! -L " + quote(path)

    private fun regularOrAbsent(path: String): String =
        "test ! -L " + quote(path) + " && { test ! -e " + quote(path) + " || test -f " + quote(path) + "; }"

    private fun pidFrom(pidFile: String): String = listOf(
        regular(pidFile) + " || exit 1",
        "pid=\$(cat " + quote(pidFile) + " 2>/dev/null) || exit 1",
        "case \"\$pid\" in ''|0*|*[!0-9]*) exit 1 ;; esac",
        "test \"\$pid\" -gt 1 2>/dev/null && test \"\$pid\" -le 2147483647 2>/dev/null || exit 1",
    ).joinToString("\n")

    private fun readBoot(procRoot: String): String = listOf(
        "boot=\$(cat " + quote("$procRoot/sys/kernel/random/boot_id") + " 2>/dev/null) || exit 1",
        "printf '%s\\n' \"\$boot\" | grep -Eq '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\$' || exit 1",
    ).joinToString("\n")

    // Field 22 follows the final command-name delimiter, even when the
    // process name itself contains spaces or parentheses.
    private fun readStat(procRoot: String): String = listOf(
        "stat=\$(cat " + quote(procRoot) + "/\$pid/stat 2>/dev/null) || exit 1",
        "case \"\$stat\" in \"\$pid (\"*) ;; *) exit 1 ;; esac",
        "rest=\${stat##*) }; test \"\$rest\" != \"\$stat\" || exit 1",
        "set -- \$rest; test \"\$#\" -ge 20 || exit 1",
        "state=\$1; ticks=\${20}",
        "case \"\$ticks\" in ''|*[!0-9]*) exit 1 ;; esac",
        "case \"\$state\" in R|S|D|T|t|I|W|P|Z|X|x) ;; *) exit 1 ;; esac",
    ).joinToString("\n")

    private const val RUNNING = "case \"\$state\" in Z|X|x) exit 1 ;; esac"

    private fun executable(procRoot: String, path: String): String =
        "test \"\$(readlink " + quote(procRoot) + "/\$pid/exe 2>/dev/null)\" = " + quote(path)

    private fun script(procRoot: String, path: String): String =
        "tr '\\000' '\\n' <" + quote(procRoot) + "/\$pid/cmdline 2>/dev/null | grep -Fxq " + quote(path)

    fun captureExecutable(pidFile: String, generation: String, path: String, procRoot: String = "/proc"): String =
        capture(pidFile, generation, executable(procRoot, path), procRoot)

    fun captureScript(pidFile: String, generation: String, path: String, procRoot: String = "/proc"): String =
        capture(pidFile, generation, script(procRoot, path), procRoot)

    private fun capture(pidFile: String, generation: String, expected: String, procRoot: String): String {
        validateGeneration(generation)
        val record = "$pidFile.identity"
        val temporary = "$record.$generation.tmp"
        return listOf(
            "(", "set -f", "umask 077",
            regularOrAbsent(record) + " && " + regularOrAbsent(temporary) + " || exit 1",
            pidFrom(pidFile),
            readBoot(procRoot),
            readStat(procRoot),
            RUNNING,
            "saved_ticks=\$ticks",
            expected + " || exit 1",
            // Verify the same task still occupies the PID after checking
            // executable/script identity. This is not an atomic pidfd check.
            readStat(procRoot),
            RUNNING,
            "test \"\$saved_ticks\" = \"\$ticks\" || exit 1",
            "printf 'v1 %s %s %s %s\\n' " + quote(generation) +
                " \"\$pid\" \"\$ticks\" \"\$boot\" > " + quote(temporary) + " || exit 1",
            "mv -f " + quote(temporary) + " " + quote(record) + " || exit 1",
            ")",
        ).joinToString("\n")
    }

    fun matchesExecutable(pidFile: String, generation: String, path: String, procRoot: String = "/proc"): String =
        probe(pidFile, generation, executable(procRoot, path), procRoot)

    fun matchesScript(pidFile: String, generation: String, path: String, procRoot: String = "/proc"): String =
        probe(pidFile, generation, script(procRoot, path), procRoot)

    /**
     * Positive same-boot proof that the recorded child is no longer the
     * task occupying this PID, or is a verified dead task. Missing proc
     * entries are ambiguous, not proof. This does not authorize a signal.
     */
    fun sameBootGone(pidFile: String, generation: String, procRoot: String = "/proc"): String =
        probe(pidFile, generation, null, procRoot)

    private fun probe(pidFile: String, generation: String, expected: String?, procRoot: String): String {
        validateGeneration(generation)
        val record = "$pidFile.identity"
        val checks = listOf(
            "(", "set -f",
            pidFrom(pidFile),
            regular(record) + " || exit 1",
            "record=\$(cat " + quote(record) + " 2>/dev/null) || exit 1",
            "set -- \$record; test \"\$#\" -eq 5 && test \"\$1\" = v1 || exit 1",
            "test \"\$2\" = " + quote(generation) + " && test \"\$3\" = \"\$pid\" || exit 1",
            "saved_ticks=\$4; saved_boot=\$5",
            "case \"\$saved_ticks\" in ''|*[!0-9]*) exit 1 ;; esac",
            readBoot(procRoot),
            "test \"\$saved_boot\" = \"\$boot\" || exit 1",
            readStat(procRoot),
        )
        val result = if (expected == null) listOf(
            "if test \"\$saved_ticks\" != \"\$ticks\"; then exit 0; fi",
            "case \"\$state\" in Z|X|x) exit 0 ;; *) exit 1 ;; esac",
        ) else listOf(
            RUNNING,
            "test \"\$saved_ticks\" = \"\$ticks\" || exit 1",
            expected + " || exit 1",
            readStat(procRoot),
            RUNNING,
            "test \"\$saved_ticks\" = \"\$ticks\" || exit 1",
        )
        return (checks + result + ")").joinToString("\n")
    }
}
