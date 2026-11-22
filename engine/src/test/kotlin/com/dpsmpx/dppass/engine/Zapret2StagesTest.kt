package com.dpsmpx.dppass.engine

import java.nio.ByteBuffer
import java.nio.ByteOrder
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull

class Zapret2StagesTest {
    private fun wire(vararg values: Long): ByteArray {
        val buffer = ByteBuffer.allocate(1 + values.size * 8).order(ByteOrder.BIG_ENDIAN)
        buffer.put(1)
        values.forEach { buffer.putLong(it) }
        return buffer.array()
    }

    @Test fun versionedCountersAreDecodedAndDeltasAreNonNegative() {
        val first = Zapret2Stages.fromWire(wire(*LongArray(15) { (it + 1).toLong() }))!!
        val second = Zapret2Stages.fromWire(wire(*LongArray(15) { (it + 3).toLong() }))!!
        val delta = second.delta(first)
        assertEquals(2L, delta.tcpDialOk)
        assertEquals(2L, delta.tcpHelloSent)
        assertEquals(2L, delta.tcpFirstTlsAlert)
        assertEquals(2L, delta.udpClosedNoReply)
        assertEquals(0L, first.delta(second).tcpDialRefused)
    }

    @Test fun malformedCountersAreNotTreatedAsHealthyZeroes() {
        assertNull(Zapret2Stages.fromWire(null))
        assertNull(Zapret2Stages.fromWire(byteArrayOf(1)))
        assertNull(Zapret2Stages.fromWire(byteArrayOf(2) + ByteArray(15 * 8)))
        assertNull(Zapret2Stages.fromWire(wire(*LongArray(15) { -1L })))
    }
}
