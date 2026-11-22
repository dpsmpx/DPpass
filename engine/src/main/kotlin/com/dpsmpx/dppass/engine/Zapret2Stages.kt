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

    /** Subtract per-session or per-window baseline, never returning negatives. */
    fun delta(previous: Zapret2Stages): Zapret2Stages =
        Zapret2Stages(LongArray(COUNT) { index -> (counters[index] - previous.counters[index]).coerceAtLeast(0L) })

    companion object {
        private const val VERSION = 1
        private const val COUNT = 15

        /** Reject malformed wire data instead of pretending there were no errors. */
        fun fromWire(wire: ByteArray?): Zapret2Stages? {
            if (wire == null || wire.size != 1 + COUNT * 8 || wire[0].toInt() != VERSION) return null
            val reader = ByteBuffer.wrap(wire).order(ByteOrder.BIG_ENDIAN)
            reader.get()
            val data = LongArray(COUNT) { reader.long }
            if (data.any { it < 0L }) return null
            return Zapret2Stages(data)
        }
    }
}
