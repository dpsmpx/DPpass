package com.dpsmpx.dppass.app

/** Called only inside the adapter lifecycle lock, after old cleanup. */
internal object RootPidfdInstall {
    private fun quote(raw: String) = "'" + raw.replace("'", "'\\''") + "'"

    fun script(directory: String, source: String, digest: String): String {
        require(digest.matches(Regex("[0-9a-f]{64}")))
        val dir = quote(directory)
        val target = quote("$directory/root-pidfd")
        return listOf(
            "(", "set -f", "umask 077",
            "test -d $dir && test ! -L $dir || exit 1",
            "test \"\$(stat -c %u $dir)\" = \"\$(id -u)\" || exit 1",
            "test ! -L $target && { test ! -e $target || test -f $target; } || exit 1",
            "tmp=\$(mktemp " + quote("$directory/.root-pidfd.XXXXXX") + ") || exit 1",
            "trap 'rm -f \"\$tmp\"' EXIT",
            "cp " + quote(source) + " \"\$tmp\" || exit 1",
            "actual=\$(sha256sum \"\$tmp\") || exit 1",
            "test \"\${actual%% *}\" = " + quote(digest) + " || { echo 'ROOT: helper checksum mismatch'; exit 1; }",
            "chmod 700 \"\$tmp\" || exit 1",
            "test \"\$(\"\$tmp\" --version)\" = dppass-root-pidfd/1 || exit 1",
            "mv -f \"\$tmp\" $target || exit 1",
            // Availability is diagnostic until strict ownership migration
            // is integrated. No signals or firewall mutations here.
            "if $target probe; then :; else echo 'ROOT: pidfd unavailable'; fi",
            ") || exit 1",
        ).joinToString("\n")
    }
}
