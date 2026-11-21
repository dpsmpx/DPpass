package com.dpsmpx.dppass.app.alpine

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.nio.file.Files
import java.nio.file.Path
import java.util.zip.GZIPOutputStream
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/** Regression tests for the DP_IDE Alpine minirootfs port. */
class AlpineTarTest {
    private data class Entry(
        val name: String,
        val body: ByteArray = byteArrayOf(),
        val type: Char = '0',
        val link: String = "",
    )

    private fun archive(vararg files: Entry): ByteArray {
        val plain = ByteArrayOutputStream()
        for (item in files) {
            val h = ByteArray(512)
            fun field(index: Int, size: Int, value: String) {
                val bytes = value.toByteArray(Charsets.US_ASCII)
                require(bytes.size < size)
                System.arraycopy(bytes, 0, h, index, bytes.size)
            }
            field(0, 100, item.name)
            field(100, 8, "0000755")
            field(124, 12, item.body.size.toString(8).padStart(11, '0'))
            h[156] = item.type.code.toByte()
            if (item.link.isNotEmpty()) field(157, 100, item.link)
            plain.write(h)
            plain.write(item.body)
            val padding = (512 - item.body.size % 512) % 512
            plain.write(ByteArray(padding))
        }
        plain.write(ByteArray(1024))
        val compressed = ByteArrayOutputStream()
        GZIPOutputStream(compressed).use { it.write(plain.toByteArray()) }
        return compressed.toByteArray()
    }

    private val shell = Entry("bin/sh", "#!/bin/sh\n".toByteArray())

    @Test
    fun extractRegularAlpineShell() {
        val dir = Files.createTempDirectory("alpine-good")
        val result = AlpineTar.unpack(ByteArrayInputStream(archive(Entry("bin/", type = '5'), shell)), dir)
        assertTrue(Files.isRegularFile(dir.resolve("bin/sh")))
        assertEquals(1, result.files)
        assertEquals("#!/bin/sh\n", Files.readString(dir.resolve("bin/sh")))
    }

    @Test
    fun neverWriteThroughSymlinksOrTraversal() {
        val base = Files.createTempDirectory("alpine-unsafe")
        val root = base.resolve("root")
        val outside = base.resolve("escaped")
        val payload = archive(
            Entry("bin/", type = '5'),
            shell,
            Entry("../escaped", "bad".toByteArray()),
            Entry("etc", type = '2', link = "../"),
            Entry("etc/escaped", "bad".toByteArray()),
            Entry("/absolute", "bad".toByteArray()),
        )
        AlpineTar.unpack(ByteArrayInputStream(payload), root)
        assertFalse(Files.exists(outside))
        assertFalse(Files.exists(base.resolve("etc/escaped")))
        assertTrue(Files.isRegularFile(root.resolve("bin/sh")))
    }

    @Test
    fun safeRelativePathsRejectEncodedTricks() {
        val root = Path.of("/tmp/guest").toAbsolutePath().normalize()
        assertNull(AlpineTar.resolveSafe(root, "/etc/passwd"))
        assertNull(AlpineTar.resolveSafe(root, "../escape"))
        assertNull(AlpineTar.resolveSafe(root, "etc/../escape"))
        assertNull(AlpineTar.resolveSafe(root, "etc//file"))
        assertNull(AlpineTar.resolveSafe(root, "etc\\file"))
        assertNotNull(AlpineTar.resolveSafe(root, "root/.profile".replace("/.", "/dot")))
    }

    @Test
    fun truncatedArchiveIsRejected() {
        val raw = archive(Entry("bin/", type = '5'), shell)
        val corrupted = raw.copyOf(raw.size / 2)
        val dir = Files.createTempDirectory("alpine-truncated")
        var failed = false
        try {
            AlpineTar.unpack(ByteArrayInputStream(corrupted), dir)
        } catch (_: java.io.IOException) {
            failed = true
        }
        assertTrue(failed)
    }
}
