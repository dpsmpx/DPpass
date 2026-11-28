package com.dpsmpx.dppass.app

import org.json.JSONObject
import org.json.JSONArray
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [26, 29, 36], manifest = Config.NONE)
class StrategyModelStatusTest {
    @Test fun snapshotCountsContextSlotsAndCalibrationSeparately() {
        val kind = Zapret2NeuralModel.Kind.STRATEGY
        val model = JSONObject(Zapret2NeuralModel.buildParameters(kind, 10_000).decodeToString())
        model.put("sparse", JSONObject().put("0", 0.2).put("9", -0.2).put("1", 0.1))
        model.put("context_observations", JSONArray("[4,2,0,0,0,0,0,0,0]"))
        model.put("observations", 6)
        model.put("verified_html_bias", JSONArray().apply {
            repeat(3) { put(JSONArray().apply { repeat(6) { put(0.0) } }) }
        })
        model.put("verified_html_observations", JSONArray("[1,0,0]"))
        val raw = model.toString().encodeToByteArray()
        val status = assertNotNull(Zapret2NeuralModel.strategyStatus(raw))
        assertEquals(10_000L, status.parameters)
        assertEquals(raw.size, status.bytes)
        assertEquals(6L, status.observations)
        assertEquals(4L, status.contexts[0].observations)
        assertEquals(2, status.contexts[0].sparse)
        assertEquals(1, status.contexts[1].sparse)
        assertEquals(minOf(10_000L - status.dense, 4096L), status.contexts.sumOf { it.quota })
        assertEquals(listOf(1L, 0L, 0L), status.html)
        assertNull(Zapret2NeuralModel.strategyStatus(byteArrayOf(1)))
    }
}
