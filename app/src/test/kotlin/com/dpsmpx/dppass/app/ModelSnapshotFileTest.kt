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

}
