package com.dpsmpx.dppass.engine

import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * Aggregate observations of experimental protected sockets only.
 * These counters reveal neither sites nor HTTP/HTTPS success. DNS/DoH and
 * normal subscriptions are outside the scope of this instrument.
 */
class Zapret2Stages private constructor(private val counters: LongArray) {
    val tcpDialOk: Long get() = counters[0]
    val tcpDialTimeout: Long get() = counters[1]
    val tcpDialRefused: Long get() = counters[2]
    val tcpDialUnreachable: Long get() = counters[3]
    val tcpDialOther: Long get() = counters[4]
    val tcpHelloSent: Long get() = counters[5]
    val tcpHelloFailed: Long get() = counters[6]
    val tcpFirstReply: Long get() = counters[7]
    val tcpClosedNoReply: Long get() = counters[8]
    val tcpFirstTlsAlert: Long get() = counters[9]
    val tcpReadTimeout: Long get() = counters[10]
    val udpInitialSent: Long get() = counters[11]
    val udpInitialFailed: Long get() = counters[12]
    val udpFirstReply: Long get() = counters[13]
    val udpClosedNoReply: Long get() = counters[14]
    /** v2: actual connected IP family or failure destination if known. */
    val tcpDialOkV4: Long get() = counters[15]
    val tcpDialOkV6: Long get() = counters[16]
    val tcpDialOkUnknown: Long get() = counters[17]
    val tcpDialUnreachableV4: Long get() = counters[18]
    val tcpDialUnreachableV6: Long get() = counters[19]
    val tcpDialUnreachableUnknown: Long get() = counters[20]

    /** Subtract per-session or per-window baseline, never returning negatives. */
    fun delta(previous: Zapret2Stages): Zapret2Stages =
        Zapret2Stages(LongArray(COUNT) { index -> (counters[index] - previous.counters[index]).coerceAtLeast(0L) })

    companion object {
        private const val VERSION = 2
        private const val COUNT = 21
        private const val OLD_COUNT = 15

        /** Backwards-compatible with 15-counter v1; reject truncated v2. */
        fun fromWire(wire: ByteArray?): Zapret2Stages? {
            if (wire == null || wire.isEmpty()) return null
            val version = wire[0].toInt()
            val count = when (version) {
                1 -> OLD_COUNT
                VERSION -> COUNT
                else -> return null
            }
            if (wire.size != 1 + count * 8) return null
            val reader = ByteBuffer.wrap(wire).order(ByteOrder.BIG_ENDIAN)
            reader.get()
            val data = LongArray(COUNT)
            repeat(count) { data[it] = reader.long }
            if (data.any { it < 0L }) return null
            return Zapret2Stages(data)
        }
    }
}
