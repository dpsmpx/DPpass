package com.dpsmpx.dppass.app

/**
 * D-120: bidirectional admission under the common ROOT lifecycle lock.
 * All checks are read-only and conservative. Metadata absence is necessary,
 * not proof that a non-cooperating process or untracked rules are absent.
 */
internal object RootHotspotInterlock {
    fun marker(lockDirectory: String): String = "$lockDirectory/hotspot.owner"
    private fun quote(value: String): String = "'" + value.replace("'", "'\\''") + "'"
    private fun absent(file: String): String =
        "test ! -e " + quote(file) + " && test ! -L " + quote(file)

    /** Run inside the existing lock, before any adapter side effects. */
    fun noClaim(lockDirectory: String): String =
        absent(marker(lockDirectory)) + " || { echo 'ROOT: hotspot ownership active or unresolved'; exit 1; }"

    private val records = listOf(
        "generation", "owner.identity", "pid", "pid6", "watch.pid",
        "pid.identity", "pid6.identity", "watch.pid.identity", "ipv6.intent", "pidfd.required",
    )

    /** Do not automatically repair or delete any adapter ownership evidence. */
    fun adaptersIdle(directories: List<String>): String = directories.joinToString("\n") { dir ->
        val path = quote(dir)
        listOf(
            "test ! -L $path || exit 1",
            "if test -e $path; then",
            "test -d $path && test \"\$(stat -c %u $path)\" = \"\$(id -u)\" || exit 1",
            records.joinToString(" && ") { absent("$dir/$it") } +
                " || { echo 'ROOT: adapter ownership active or unresolved'; exit 1; }",
            // Interrupted publication may leave an uncommitted generation.
            // Unmatched globs are harmless; dangling links are not.
            "for pending in $path/generation.*.tmp $path/owner.identity.*.tmp; do",
            "test ! -e \"\$pending\" && test ! -L \"\$pending\" || exit 1",
            "done",
            "fi",
        ).joinToString("\n")
    }.ifEmpty { ":" }
}
