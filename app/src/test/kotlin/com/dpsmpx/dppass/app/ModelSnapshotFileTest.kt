package com.dpsmpx.dppass.app

import java.io.File
import java.nio.file.Files
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class ModelSnapshotFileTest {
    @Test
    fun writesAndReplacesWithoutLeavingTemporaryFiles() {
        val root = Files.createTempDirectory("model-snapshot-test").toFile()
        try {
            val dest = File(root, "models/strategy-v2.json")
            val first = "first snapshot".encodeToByteArray()
            val second = "second snapshot".encodeToByteArray()
            assertTrue(ModelSnapshotFile.replace(dest, first))
            assertContentEquals(first, dest.readBytes())
            assertTrue(ModelSnapshotFile.replace(dest, second))
            assertContentEquals(second, dest.readBytes())
            assertTrue(dest.parentFile!!.listFiles()!!.map { it.name } == listOf(dest.name))
        } finally {
            root.deleteRecursively()
        }
    }

    @Test
    fun failedReplacementDoesNotDeleteExistingDataOrLeaveTemporaryFiles() {
        val root = Files.createTempDirectory("model-snapshot-failure").toFile()
        try {
            val dest = File(root, "occupied").apply { mkdir() }
            val existing = File(dest, "existing").apply { writeText("keep") }
            assertFalse(ModelSnapshotFile.replace(dest, byteArrayOf(1)))
            assertTrue(existing.readText() == "keep")
            assertTrue(root.listFiles()!!.map { it.name } == listOf(dest.name))
            val blocker = File(root, "blocker").apply { writeText("keep too") }
            assertFalse(ModelSnapshotFile.replace(File(blocker, "model.json"), byteArrayOf(2)))
            assertTrue(blocker.readText() == "keep too")
        } finally {
            root.deleteRecursively()
        }
    }
    @Test
    fun boundedReadRejectsMissingEmptyOversizedAndNonRegularFiles() {
        val root = Files.createTempDirectory("model-read-test").toFile()
        try {
            val file = File(root, "model.json")
            kotlin.test.assertNull(ModelSnapshotFile.readBounded(file, 16))
            kotlin.test.assertNull(ModelSnapshotFile.readBounded(root, 16))
            file.writeBytes(byteArrayOf())
            kotlin.test.assertNull(ModelSnapshotFile.readBounded(file, 16))
            val exact = ByteArray(16) { it.toByte() }
            file.writeBytes(exact)
            assertContentEquals(exact, ModelSnapshotFile.readBounded(file, 16))
            file.writeBytes(ByteArray(17))
            kotlin.test.assertNull(ModelSnapshotFile.readBounded(file, 16))
        } finally {
            root.deleteRecursively()
        }
    }

    @Test
    fun staleSnapshotCannotOverwriteNewOrDeletedFile() {
        val root = Files.createTempDirectory("model-cas-test").toFile()
        try {
            val file = File(root, "model.json")
            val original = byteArrayOf(1, 2)
            val replacement = byteArrayOf(3, 4)
            val stale = byteArrayOf(5, 6)
            assertTrue(ModelSnapshotFile.replace(file, original))
            assertTrue(ModelSnapshotFile.replaceIfUnchanged(file, original, replacement, 16))
            assertFalse(ModelSnapshotFile.replaceIfUnchanged(file, original, stale, 16))
            assertContentEquals(replacement, file.readBytes())
            assertFalse(ModelSnapshotFile.replaceIfUnchanged(file, replacement, ByteArray(17), 16))
            assertContentEquals(replacement, file.readBytes())
            assertTrue(file.delete())
            assertFalse(ModelSnapshotFile.replaceIfUnchanged(file, replacement, stale, 16))
            assertFalse(file.exists())
        } finally {
            root.deleteRecursively()
        }
    }

    @Test
    fun equalCounterSnapshotsStillRequireExactBaseBytes() {
        val root = Files.createTempDirectory("model-equal-counters").toFile()
        try {
            val file = File(root, "model.json")
            val base = """{"observations":20,"weight":0}""".encodeToByteArray()
            val newer = """{"observations":20,"weight":1}""".encodeToByteArray()
            val stale = """{"observations":20,"weight":2}""".encodeToByteArray()
            assertTrue(ModelSnapshotFile.replace(file, base))
            assertTrue(ModelSnapshotFile.replaceIfUnchanged(file, base, newer, 128))
            assertFalse(ModelSnapshotFile.replaceIfUnchanged(file, base, stale, 128))
            assertContentEquals(newer, file.readBytes())
        } finally {
            root.deleteRecursively()
        }
    }

}
