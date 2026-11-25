package com.dpsmpx.dppass.app

import java.util.UUID

/**
 * Per-adapter transaction for the existing private ROOT directory.
 * The lock inode is stable, and a generation is published before any
 * cleanup or launch. An obsolete adapter/watchdog cannot clean a new one.
 * Old versions that do not honor this lock still require migration tests.
 */
internal class RootLifecycleTransaction(
    private val directory: String,
    private val generation: String = UUID.randomUUID().toString(),
) {
    private val lock = "$directory/lifecycle.lock"
    private val record = "$directory/generation"

    private fun quote(value: String): String = "'" + value.replace("'", "'\\''") + "'"

    init {
        // Validate even before rendering a startup script.
        RootProcessIdentity.generationMatches(record, generation)
    }

    private fun transaction(body: String): String =
        RootProcessIdentity.lockedTransaction(lock, body)

    fun start(cleanup: String, launch: String): String {
        val temporary = "$record.$generation.tmp"
        return listOf(
            "set -eu",
            "umask 077",
            "mkdir -p " + quote(directory),
            "chmod 700 " + quote(directory),
            transaction(listOf(
                "set -eu",
                "printf '%s\\n' " + quote(generation) + " > " + quote(temporary),
                "mv -f " + quote(temporary) + " " + quote(record),
                // Cleanup may set shell options or exit explicitly.
                "(\n$cleanup\n) || exit 1",
                launch,
            ).joinToString("\n")),
        ).joinToString("\n")
    }

    fun stop(cleanup: String): String = listOf(
        // Do not create an absent ROOT directory during a stop.
        "test -d " + quote(directory) + " || exit 0",
        transaction(listOf(
            "test -e " + quote(record) + " || exit 0",
            "current=\$(cat " + quote(record) + ") || exit 1",
            "test \"\$current\" = " + quote(generation) + " || exit 0",
            "(\n$cleanup\n) || exit 1",
            "rm -f " + quote(record) + " || exit 1",
        ).joinToString("\n")),
    ).joinToString("\n")

    fun alive(check: String): String = transaction(
        RootProcessIdentity.generationMatches(record, generation) + " && (\n$check\n)",
    )

    fun watchdog(condition: String, cleanup: String): String =
        "while $condition; do sleep 3; done\n" +
            // A busy lifecycle lock or incomplete cleanup must not silently
            // terminate the watchdog. Generation mismatch is a safe no-op.
            "while ! (\n" + stop(cleanup) + "\n); do sleep 3; done"
}
