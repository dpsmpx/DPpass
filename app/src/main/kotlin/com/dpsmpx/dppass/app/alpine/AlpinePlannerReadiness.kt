package com.dpsmpx.dppass.app.alpine

import java.io.InputStream

/** Fixed startup exchange with the bundled Go planner, not user traffic.
 * Both sides deliberately pin the canonical encoding; a changed wire
 * contract must update the Go and JVM fixtures together.
 */
internal object AlpinePlannerReadiness {
    private const val REQUEST = "{\"tag\":\"dppass:exp-split-1\",\"network\":\"tcp\",\"first\":\"FgMBAAQBAAAA\"}\n"
    private const val EXPECTED = "{\"plan\":{\"strategy\":\"dppass:exp-split-1\",\"network\":\"tcp\",\"applied\":true,\"cut\":1}}\n"

    fun request(): ByteArray = REQUEST.toByteArray(Charsets.UTF_8)

    fun validSocketPath(path: String): Boolean =
        path.startsWith("/") && '\u0000' !in path &&
            path.toByteArray(Charsets.UTF_8).size <= 99

    // The expected reply is ASCII. Compare one bounded frame without
    // unbounded readLine allocation; fail on the first differing byte.
    // The socket owner sets the read timeout.
    fun matches(input: InputStream): Boolean {
        for (expected in EXPECTED) {
            if (input.read() != expected.code) return false
        }
        return true
    }
}
