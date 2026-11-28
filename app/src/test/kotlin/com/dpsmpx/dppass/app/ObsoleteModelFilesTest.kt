package com.dpsmpx.dppass.app

import java.io.File
import java.nio.file.Files
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

class ObsoleteModelFilesTest {
    private fun withDirectory(block: (File) -> Unit) {
        val root = Files.createTempDirectory("obsolete-models").toFile()
        try { block(root) } finally { root.deleteRecursively() }
    }
    private fun model(root: File, name: String, format: String) =
        File(root, name).apply { writeText("""{"format":"$format","observations":0}""") }

    @Test fun deletesOnlyPreviewedObsoleteModelsAndPendingWrites() = withDirectory { root ->
        val old = model(root, "strategy-v2.json", "dppass-strategy-mlp-v4:tcp=split;quic=pass")
        val pending = File(root, ".model-123.pending").apply { writeBytes(byteArrayOf()) }
        val server = model(root, "server-v1.json", "dppass-server-mlp-v4")
        val active = model(root, "strategy-v5.json", "dppass-strategy-mlp-v5:tcp=split;quic=pass")
        val unrelated = File(root, "subscription.json").apply { writeText("keep") }
        val unknown = File(root, ".model-other.pending").apply { writeText("keep") }
        val preview = requireNotNull(ObsoleteModelFiles.scan(root))
        assertEquals(listOf(pending.name, old.name), preview.map { it.name })
        assertEquals(old.length(), preview.sumOf { it.bytes })
        val result = ObsoleteModelFiles.clean(root, preview)
        assertFalse(result.changed)
        assertEquals(preview, result.removed)
        assertTrue(result.failed.isEmpty())
        assertFalse(old.exists())
        assertFalse(pending.exists())
        assertTrue(listOf(server, active, unrelated, unknown).all { it.exists() })
    }

    @Test fun retiredServerFormatButNotCurrentOrUnknownCanBeRemoved() = withDirectory { root ->
        val server = model(root, "server-v1.json", "dppass-server-mlp-v3")
        val preview = requireNotNull(ObsoleteModelFiles.scan(root))
        assertEquals(ObsoleteModelFiles.Reason.RETIRED_SERVER, preview.single().reason)
        server.writeText("""{"format":"dppass-server-mlp-v4"}""")
        assertTrue(ObsoleteModelFiles.clean(root, preview).changed)
        assertTrue(server.exists())
        server.writeText("""{"format":"future"}""")
        assertTrue(requireNotNull(ObsoleteModelFiles.scan(root)).isEmpty())
        server.writeText("""{"format":"dppass-server-mlp-v3","format":"dppass-server-mlp-v4"}""")
        assertTrue(requireNotNull(ObsoleteModelFiles.scan(root)).isEmpty())
    }

    @Test fun sameSizeModificationAndAddedFileInvalidatePreview() = withDirectory { root ->
        val old = model(root, "strategy-v2.json", "dppass-strategy-mlp-v4")
        val preview = requireNotNull(ObsoleteModelFiles.scan(root))
        old.writeText(old.readText().replace("observations\":0", "observations\":1"))
        assertTrue(ObsoleteModelFiles.clean(root, preview).changed)
        assertTrue(old.exists())
        val next = requireNotNull(ObsoleteModelFiles.scan(root))
        File(root, ".model-1.pending").writeText("new")
        assertTrue(ObsoleteModelFiles.clean(root, next).changed)
        assertTrue(old.exists())
    }

    @Test fun ignoresSymlinksDirectoriesOversizedAndUnrecognizedModels() = withDirectory { root ->
        val target = File(root, "keep.json").apply { writeText("""{"format":"dppass-strategy-mlp-v4"}""") }
        Files.createSymbolicLink(File(root, "strategy-v2.json").toPath(), target.toPath())
        File(root, ".model-1.pending").mkdir()
        File(root, ".model-2.pending").writeBytes(ByteArray(1_048_577))
        model(root, "server-v1.json", "future")
        assertTrue(requireNotNull(ObsoleteModelFiles.scan(root)).isEmpty())
        assertTrue(target.exists())
        val alias = File(root, "alias")
        Files.createSymbolicLink(alias.toPath(), root.toPath())
        assertNull(ObsoleteModelFiles.scan(alias))
        Files.delete(alias.toPath())
        Files.delete(File(root, "strategy-v2.json").toPath())
    }

    @Test fun formatMarkerMustBeTopLevelAndUnambiguous() {
        fun format(raw: String) = ModelJsonPreflight.format(raw.encodeToByteArray(), 1024)
        assertEquals("old", format("""{"sparse":{"format":"fake"},"format":"old"}"""))
        assertNull(format("""{"sparse":{"format":"old"}}"""))
        assertNull(format("""{"format":"old","format":"new"}"""))
        assertNull(format("""{"format":12}"""))
    }
}
