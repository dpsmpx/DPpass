package com.dpsmpx.dppass.app

import java.io.File
import java.io.InputStream
import java.io.IOException
import java.security.MessageDigest
import java.util.zip.ZipFile

/** Artifact identity only; not evidence of a native execution or peer reply. */
internal class DptsBuildIdentity private constructor(
    val version: String,
    val splitCount: Int,
    val baseDigest: String?,
    val arm64JniDigest: String?,
) {
    fun report(): String =
        "BUILD: version=$version; split_count=$splitCount;" +
            " base_apk_sha256=${baseDigest ?: "unavailable"};" +
            " apk_arm64_jni_sha256=${arm64JniDigest ?: "unavailable"};" +
            " single_apk_identity=${splitCount == 0 && baseDigest != null && arm64JniDigest != null};" +
            " physical_network_acceptance=not_measured"

    companion object {
        private const val JNI = "lib/arm64-v8a/libdppassxray.so"
        private val versionPattern = Regex("[A-Za-z0-9._+\\-]{1,80}")

        fun capture(baseApk: File, splitCount: Int, version: String,
            checkActive: () -> Unit = {}): DptsBuildIdentity {
            val safeVersion = version.takeIf { versionPattern.matches(it) } ?: "unknown"
            checkActive()
            val base = readable {
                baseApk.inputStream().use { digest(it, checkActive) }
            }
            checkActive()
            val jni = readable {
                ZipFile(baseApk).use { zip ->
                    val matches = zip.entries().asSequence().filter { it.name == JNI }.take(2).toList()
                    val entry = matches.singleOrNull()?.takeUnless { it.isDirectory }
                        ?: return@use null
                    zip.getInputStream(entry).use { digest(it, checkActive) }
                }
            }
            checkActive()
            return DptsBuildIdentity(safeVersion, splitCount.coerceAtLeast(0), base, jni)
        }

        // Catch only filesystem/archive failures; cancellation and unexpected
        // runtime errors must not be hidden as successful identity capture.
        private fun readable(block: () -> String?): String? = try {
            block()
        } catch (_: IOException) {
            null
        } catch (_: SecurityException) {
            null
        }

        private fun digest(input: InputStream, checkActive: () -> Unit): String {
            val hash = MessageDigest.getInstance("SHA-256")
            val buffer = ByteArray(64 * 1024)
            while (true) {
                checkActive()
                val n = input.read(buffer)
                if (n < 0) break
                if (n > 0) hash.update(buffer, 0, n)
            }
            val digits = "0123456789abcdef"
            return buildString(64) {
                for (byte in hash.digest()) {
                    val value = byte.toInt() and 255
                    append(digits[value ushr 4])
                    append(digits[value and 15])
                }
            }
        }
    }
}
