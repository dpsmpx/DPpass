package com.dpsmpx.dppass.app

/** Initialize only the private shared lock directory. Never remove or reset
 * existing metadata, lock inode, adapters, firewall or routing state. */
internal object RootHotspotEnvironment {
    fun initialize(directory: String = RootLifecycleTransaction.SHARED_LOCK_DIRECTORY): String {
        require(directory.startsWith("/") && directory != "/" && !directory.endsWith("/") &&
            directory.none { it == '\u0000' || it == '\n' || it == '\r' })
        val file = java.io.File(directory)
        require(file.name !in setOf(".", ".."))
        val path = quote(directory)
        val parent = quote(requireNotNull(file.parent))
        val validate = "test -d $path && test ! -L $path && " +
            "test \"\$(stat -c %u $path)\" = \"\$(id -u)\""
        return listOf(
            "set -eu",
            "umask 077",
            "test -d $parent && test ! -L $parent || exit 1",
            "test \"\$(stat -c %u $parent)\" = \"\$(id -u)\" || exit 1",
            "test ! -L $path || exit 1",
            "if test ! -e $path; then",
            // Concurrent cooperating mkdir is harmless only if subsequent
            // owner and directory checks succeed. Never follow symlinks.
            "mkdir -m 700 $path 2>/dev/null || ( $validate ) || exit 1",
            "fi",
            "$validate || exit 1",
            "test \"\$(stat -c %a $path)\" = 700 || exit 1",
            RootProcessIdentity.lockedTransaction("$directory/lifecycle.lock",
                "$validate || exit 1\n" +
                    "test \"\$(stat -c %a $path)\" = 700 || exit 1\n" +
                    "printf 'environment_ready\\n'"),
        ).joinToString("\n")
    }
    private fun quote(value: String): String = "'" + value.replace("'", "'\\''") + "'"
}
