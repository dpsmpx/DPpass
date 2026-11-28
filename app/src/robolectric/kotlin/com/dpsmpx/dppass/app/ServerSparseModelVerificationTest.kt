package com.dpsmpx.dppass.app

import org.json.JSONArray
import org.json.JSONObject
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import kotlin.test.assertFalse
import kotlin.test.assertTrue

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [26, 29, 36], manifest = Config.NONE)
class ServerSparseModelVerificationTest {
    private val server = Zapret2NeuralModel.Kind.SERVER

    @Test fun oldV4StillLoadsAndRecencyUsesOnlyCurrentNumericIndices() {
        val model = JSONObject(Zapret2NeuralModel.buildParameters(server, 10_000).decodeToString())
        model.put("sparse", JSONObject().put("0", 0.5).put("6", -0.5))
        assertTrue(verify(model))
        model.put("sparse_recency", JSONArray("[6,0]"))
        assertTrue(verify(model))
        for (order in listOf("[0,0]", "[6,12]", "[6,\"0\"]", "[6,0.5]", "[6]")) {
            model.put("sparse_recency", JSONArray(order))
            assertFalse(verify(model), order)
        }
    }

    @Test fun onlyLegacyV4CanExceedTheNewPerContextQuota() {
        val model = JSONObject(Zapret2NeuralModel.buildParameters(server, 10_000).decodeToString())
        val sparse = JSONObject()
        val recency = JSONArray()
        repeat(ServerSparseWeights.quota(0, 10_000) + 1) {
            val index = it * 6L
            sparse.put(index.toString(), 0.5)
            recency.put(index)
        }
        model.put("sparse", sparse)
        assertTrue(verify(model))
        model.put("sparse_recency", recency)
        assertFalse(verify(model))
        sparse.remove("0")
        recency.remove(0)
        assertTrue(verify(model))
    }

    @Test fun strategyRejectsServerRecencyField() {
        val strategy = Zapret2NeuralModel.Kind.STRATEGY
        val model = JSONObject(Zapret2NeuralModel.buildParameters(strategy, 10_000).decodeToString())
        assertTrue(Zapret2NeuralModel.verify(model.toString().encodeToByteArray(), strategy))
        model.put("sparse_recency", JSONArray())
        assertFalse(Zapret2NeuralModel.verify(model.toString().encodeToByteArray(), strategy))
    }

    private fun verify(model: JSONObject): Boolean =
        Zapret2NeuralModel.verify(model.toString().encodeToByteArray(), server)
}
