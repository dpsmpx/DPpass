package com.dpsmpx.dppass.app

import java.io.File
import java.security.MessageDigest
import java.util.concurrent.CancellationException
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir

class DptsBuildIdentityTest {
    @TempDir lateinit var directory: File

    private fun sha(bytes: ByteArray): String =
        MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }

    private fun apk(name: String, entry: String, content: ByteArray): File =
        File(directory, name).also { file ->
            ZipOutputStream(file.outputStream()).use { zip ->
                zip.putNextEntry(ZipEntry(entry))
                zip.write(content)
                zip.closeEntry()
            }
        }

    @Test fun comparesActualApkAndPackagedJniDigests() {
        val content = ByteArray(160_000) { (it * 37).toByte() }
        val file = apk("candidate.apk", "lib/arm64-v8a/libdppassxray.so", content)
        val identity = DptsBuildIdentity.capture(file, 0, "0.8.3-rc.7-dev")
        assertEquals(sha(file.readBytes()), identity.baseDigest)
        assertEquals(sha(content), identity.arm64JniDigest)
        assertTrue(identity.report().contains("single_apk_identity=true"))
        assertFalse(identity.report().contains(file.absolutePath))
        val report = DptsLocalSuite.ACCEPTANCE.report(emptyList(), buildIdentity = identity)
        assertTrue(report.contains(identity.report()))
        assertTrue(report.contains("ACCEPTANCE: NOT_VERIFIED"))
    }

    @Test fun missingJniAndSplitInstallAreExplicit() {
        val file = apk("split.apk", "lib/x86_64/libdppassxray.so", byteArrayOf(1, 2, 3))
        val identity = DptsBuildIdentity.capture(file, 2, "bad\nprivate")
        assertEquals("unknown", identity.version)
        assertNull(identity.arm64JniDigest)
        assertTrue(identity.report().contains("split_count=2"))
        assertTrue(identity.report().contains("single_apk_identity=false"))
        assertFalse(identity.report().contains("private"))
    }

    @Test fun missingOrInvalidArchiveDoesNotInventDigest() {
        val missing = DptsBuildIdentity.capture(File(directory, "missing.apk"), 0, "1")
        assertNull(missing.baseDigest)
        assertNull(missing.arm64JniDigest)
        assertTrue(missing.report().contains("single_apk_identity=false"))
        val invalid = File(directory, "invalid.apk").apply { writeText("not an APK") }
        val readable = DptsBuildIdentity.capture(invalid, 0, "1")
        assertEquals(sha(invalid.readBytes()), readable.baseDigest)
        assertNull(readable.arm64JniDigest)
    }

    @Test fun cancellationPropagatesDuringHashing() {
        val file = apk("cancel.apk", "lib/arm64-v8a/libdppassxray.so", ByteArray(200_000))
        var checks = 0
        assertThrows(CancellationException::class.java) {
            DptsBuildIdentity.capture(file, 0, "1") {
                if (++checks == 4) throw CancellationException("cancelled")
            }
        }
        assertEquals(4, checks)
    }
}
