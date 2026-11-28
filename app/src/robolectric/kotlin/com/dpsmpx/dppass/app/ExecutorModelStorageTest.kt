package com.dpsmpx.dppass.app

import com.dpsmpx.dppass.app.Zapret2NeuralModel.Kind
import java.io.File
import java.nio.file.Files
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue
import org.json.JSONArray
import org.json.JSONObject
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [26, 29, 36], manifest = Config.NONE)
class ExecutorModelStorageTest {
    @Test
    fun exactModelKindIsRequiredOnDisk() = withDirectory { directory ->
        val models = Kind.entries.associateWith { Zapret2NeuralModel.build(it, 32) }
        assertEquals(models.size, models.keys.map { it.filename }.distinct().size)
        for ((destination, own) in models) {
            assertTrue(Zapret2NeuralModel.store(directory, destination, own))
            for ((source, foreign) in models) {
                if (source == destination) continue
                assertFalse(Zapret2NeuralModel.store(directory, destination, foreign), "$source to $destination")
                assertContentEquals(own, Zapret2NeuralModel.readVerified(directory, destination))
            }
        }
        File(directory, Kind.ROOT_PACKET.filename).writeBytes(models.getValue(Kind.ROOT_SOCKET))
        assertNull(Zapret2NeuralModel.readVerified(directory, Kind.ROOT_PACKET))
        assertContentEquals(models.getValue(Kind.ROOT_SOCKET), Zapret2NeuralModel.readVerified(directory, Kind.ROOT_SOCKET))
    }

    @Test
    fun learnedSnapshotReplacesOnlyItsOwnCurrentFile() = withDirectory { directory ->
        val root = Zapret2NeuralModel.build(Kind.ROOT_SOCKET, 32)
        val vpn = Zapret2NeuralModel.build(Kind.STRATEGY, 32)
        val packet = Zapret2NeuralModel.build(Kind.ROOT_PACKET, 32)
        assertTrue(Zapret2NeuralModel.store(directory, Kind.ROOT_SOCKET, root))
        assertTrue(Zapret2NeuralModel.store(directory, Kind.STRATEGY, vpn))
        assertTrue(Zapret2NeuralModel.store(directory, Kind.ROOT_PACKET, packet))
        val next = JSONObject(root.decodeToString()).apply {
            put("observations", 1)
            getJSONArray("context_observations").put(0, 1)
        }.toString().encodeToByteArray()
        assertFalse(Zapret2NeuralModel.storeLearnedSnapshot(directory, Kind.STRATEGY, next, vpn))
        assertFalse(Zapret2NeuralModel.storeLearnedSnapshot(directory, Kind.ROOT_PACKET, next, packet))
        assertTrue(Zapret2NeuralModel.storeLearnedSnapshot(directory, Kind.ROOT_SOCKET, next, root))
        assertFalse(Zapret2NeuralModel.storeLearnedSnapshot(directory, Kind.ROOT_SOCKET, root, next))
        assertFalse(Zapret2NeuralModel.storeLearnedSnapshot(directory, Kind.ROOT_SOCKET, next, root))
        assertContentEquals(next, Zapret2NeuralModel.readVerified(directory, Kind.ROOT_SOCKET))
        assertContentEquals(vpn, Zapret2NeuralModel.readVerified(directory, Kind.STRATEGY))
        assertContentEquals(packet, Zapret2NeuralModel.readVerified(directory, Kind.ROOT_PACKET))
    }

    @Test
    fun rootValidationRejectsVpnCalibrationAndEnforcesContextQuota() {
        for (kind in listOf(Kind.ROOT_SOCKET, Kind.ROOT_PACKET)) {
            val raw = Zapret2NeuralModel.buildParameters(kind, 100_000)
            assertTrue(Zapret2NeuralModel.verify(raw, kind))
            for (field in listOf("verified_html_bias", "verified_html_observations")) {
                val withCalibration = JSONObject(raw.decodeToString()).put(field, JSONArray())
                assertFalse(Zapret2NeuralModel.verify(withCalibration.toString().encodeToByteArray(), kind))
            }
            val tooMany = JSONObject(raw.decodeToString())
            val sparse = tooMany.getJSONObject("sparse")
            val firstContextQuota = 1 + (Zapret2NeuralModel.MAX_SPARSE_ENTRIES - 1) / kind.contexts
            repeat(firstContextQuota + 1) { index -> sparse.put((index * kind.contexts).toString(), 0.25) }
            assertFalse(Zapret2NeuralModel.verify(tooMany.toString().encodeToByteArray(), kind))
        }
    }

    private fun withDirectory(block: (File) -> Unit) {
        val directory = Files.createTempDirectory("executor-models").toFile()
        try {
            block(directory)
        } finally {
            directory.deleteRecursively()
        }
    }
}
