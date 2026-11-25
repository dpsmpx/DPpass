package com.dpsmpx.dppass.app

/**
 * Remove only exact rules belonging to an adapter. A failed -C is not
 * proof of absence: a successful fresh listing must also contain no
 * matching ownership marker. Unexpected rules are never deleted here.
 */
internal object RootFirewallCleanup {
    enum class Kind(val table: String, val marker: String) {
        SOCKET("nat", "(^|[[:space:]])--comment[[:space:]]+(\"dppass-byedpi\"|'dppass-byedpi'|dppass-byedpi)([[:space:]]|$)"),
        PACKET("mangle", "(^|[[:space:]])--queue-num[[:space:]]+20529([[:space:]]|$)"),
    }

    private fun quote(raw: String) = "'" + raw.replace("'", "'\\''") + "'"

    /** A successful -S exit alone is insufficient. OUTPUT is a built-in
     * chain: require exactly one policy and only its rule records. */
    private fun validateListing(): List<String> = listOf(
        "policy_count=\$(printf '%s\\n' \"\$listing\" | grep -Ec " +
            quote("^-P OUTPUT (ACCEPT|DROP)$") + ") || exit 1",
        "test \"\$policy_count\" -eq 1 || { echo 'ROOT: invalid OUTPUT policy'; exit 1; }",
        "printf '%s\\n' \"\$listing\" | grep -Ev " +
            quote("^(-P OUTPUT (ACCEPT|DROP)|-A OUTPUT .+)$") + " >/dev/null",
        "test \"\$?\" -eq 1 || { echo 'ROOT: invalid OUTPUT listing'; exit 1; }",
    )

    // For an inaccessible optional IPv6 table, a persisted intent means
    // cleanup cannot be confirmed. Old installs lacking intent metadata
    // retain the legacy optional-table behavior, pending migration tests.
    fun remove(kind: Kind, command: String, rules: List<String>, optional: Boolean = false,
               intentFile: String? = null): String {
        require(command == "iptables" || command == "ip6tables")
        require(rules.isNotEmpty())
        require(!optional || intentFile != null)
        val prefix = "$command -t " + kind.table
        val body = buildList {
            add("set +e")
            if (intentFile != null) {
                val intent = quote(intentFile)
                add("test ! -L $intent && { test ! -e $intent || test -f $intent; } || exit 1")
            }
            add("if ! listing=\$( $prefix -S OUTPUT 2>/dev/null ); then")
            if (optional) {
                val intent = quote(requireNotNull(intentFile))
                add("if test -e $intent || test -L $intent; then echo 'ROOT: IPv6 cleanup unconfirmed'; exit 1; fi")
                add("exit 0")
            } else {
                add("echo 'ROOT: firewall listing unavailable'; exit 1")
            }
            add("fi")
            addAll(validateListing())
            for (rule in rules) {
                add("remaining=32")
                add("while $prefix -C OUTPUT $rule 2>/dev/null; do")
                add("test \"\$remaining\" -gt 0 || { echo 'ROOT: firewall cleanup bound exceeded'; exit 1; }")
                add("$prefix -D OUTPUT $rule || exit 1")
                add("remaining=\$((remaining-1))")
                add("done")
            }
            add("listing=\$( $prefix -S OUTPUT ) || { echo 'ROOT: firewall verification unavailable'; exit 1; }")
            addAll(validateListing())
            add("printf '%s\\n' \"\$listing\" | grep -E " + quote(kind.marker) + " >/dev/null")
            add("status=\$?")
            add("test \"\$status\" -eq 1 || { echo 'ROOT: firewall rules remain or verification failed'; exit 1; }")
            if (intentFile != null) add("rm -f " + quote(intentFile) + " || exit 1")
            add("exit 0")
        }
        return "(\n" + body.joinToString("\n") + "\n) || exit 1"
    }

    /** Persist intent before installing the first IPv6 rule. The parent
     * directory is private and the caller holds the lifecycle lock. */
    fun markIntent(path: String): String {
        val file = quote(path)
        return "test ! -L $file && { test ! -e $file || test -f $file; } || exit 1\n" +
            "printf '%s\\n' v1 > $file || exit 1"
    }
}
