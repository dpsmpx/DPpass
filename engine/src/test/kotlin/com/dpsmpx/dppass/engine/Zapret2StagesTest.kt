package com.dpsmpx.dppass.engine

import java.nio.ByteBuffer
import java.nio.ByteOrder
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull

class Zapret2StagesTest {
    private fun wire(vararg values: Long, version: Int = 1): ByteArray {
        val buffer = ByteBuffer.allocate(1 + values.size * 8).order(ByteOrder.BIG_ENDIAN)
        buffer.put(version.toByte())
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

    @Test fun v2PreservesOriginalCountersAndReportsNetworkFamilies() {
        val original = LongArray(21)
        original[0] = 9
        original[3] = 7
        original[15] = 4 // connected IPv4
        original[16] = 4 // connected IPv6
        original[17] = 1 // connected unknown
        original[18] = 2 // unreachable IPv4
        original[19] = 3 // unreachable IPv6
        original[20] = 2 // unreachable unknown
        val stats = Zapret2Stages.fromWire(wire(*original, version = 2))!!
        assertEquals(9L, stats.tcpDialOk)
        assertEquals(7L, stats.tcpDialUnreachable)
        assertEquals(4L, stats.tcpDialOkV4)
        assertEquals(4L, stats.tcpDialOkV6)
        assertEquals(1L, stats.tcpDialOkUnknown)
        assertEquals(2L, stats.tcpDialUnreachableV4)
        assertEquals(3L, stats.tcpDialUnreachableV6)
        assertEquals(2L, stats.tcpDialUnreachableUnknown)
        assertEquals(0L, Zapret2Stages.fromWire(wire(*LongArray(15)))!!.tcpDialUnreachableV6)
        assertNull(Zapret2Stages.fromWire(wire(*LongArray(15), version = 2)))
    }

    @Test fun v3ReportsNativePlansWithoutChangingOldCounters() {
        val values = LongArray(23)
        values[0] = 9
        values[21] = 7
        values[22] = 2
        val stats = Zapret2Stages.fromWire(wire(*values, version = 3))!!
        val old = Zapret2Stages.fromWire(wire(*LongArray(21), version = 2))!!
        assertEquals(9L, stats.tcpDialOk)
        assertEquals(7L, stats.nativeTlsEncoded)
        assertEquals(2L, stats.nativeTlsReferenceFallback)
        assertEquals(0L, old.nativeTlsEncoded)
        assertEquals(7L, stats.delta(old).nativeTlsEncoded)
        assertNull(Zapret2Stages.fromWire(wire(*LongArray(21), version = 3)))
    }

    @Test fun malformedCountersAreNotTreatedAsHealthyZeroes() {
        assertNull(Zapret2Stages.fromWire(null))
        assertNull(Zapret2Stages.fromWire(byteArrayOf(1)))
        assertNull(Zapret2Stages.fromWire(byteArrayOf(2) + ByteArray(15 * 8)))
        assertNull(Zapret2Stages.fromWire(wire(*LongArray(15) { -1L })))
    }
}
