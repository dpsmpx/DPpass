package com.dpsmpx.dppass.app

import com.dpsmpx.dppass.app.RootHotspotIngress.Action
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test

class RootHotspotIngressTest {
    @Test fun onlyIpv4TcpAndDnsReachTheGatewayHandlers() {
        assertEquals(Action.TCP, classify(packet(6, 443)))
        assertEquals(Action.DNS, classify(packet(6, 53)))
        assertEquals(Action.DNS, classify(packet(17, 53)))
        assertEquals(Action.DROP, classify(packet(17, 443)))
        assertEquals(Action.DROP, classify(packet(1, 53)))
        assertEquals(Action.DROP, classify(packet(6, 0)))
    }

    @Test fun dropsMalformedHeadersFragmentsAndIpv6WithoutReadingPastSize() {
        val valid = packet(6, 443)
        for (size in -1 until valid.size) {
            assertEquals(Action.DROP, RootHotspotIngress.classify(valid, size))
        }
        assertEquals(Action.DROP, RootHotspotIngress.classify(valid, valid.size + 1))
        assertEquals(Action.TCP, classify(valid.copyOf().apply { this[6] = 0x40 }))
        for ((offset, value) in listOf(0 to 0x60, 0 to 0x46, 6 to 0x20, 7 to 1, 32 to 0x40, 32 to 0x60)) {
            assertEquals(Action.DROP, classify(valid.copyOf().apply { this[offset] = value.toByte() }))
        }
        assertEquals(Action.DROP, classify(packet(17, 53).apply { this[25] = 8 }))
    }

    private fun classify(packet: ByteArray) = RootHotspotIngress.classify(packet, packet.size)

    private fun packet(protocol: Int, port: Int): ByteArray = ByteArray(40).apply {
        this[0] = 0x45
        this[3] = size.toByte()
        this[9] = protocol.toByte()
        this[20] = 0x30
        this[21] = 0x39
        this[22] = (port ushr 8).toByte()
        this[23] = port.toByte()
        this[25] = 20
        this[32] = 0x50
    }
}
