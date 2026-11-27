package com.dpsmpx.dppass.app

import com.dpsmpx.dppass.engine.TunInput
import java.io.Closeable
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class RootHotspotTunHandoffTest {
    private val session = RootHotspotAdmission.Session(9, 12, RootHotspotAdmission.Mode.VPN)
    private val receipt = RootHotspotTunLaunch.Receipt(RootHotspotTunLifetime.Identity(session, "dpgateway", 42), 123)

    private inner class Fixture {
        val calls = mutableListOf<String>()
        var response: RootHotspotTunLaunch.Receipt? = receipt
        var failOpen = false
        var failReceive = false
        var failClose = false
        var failDiscard = false
        var failDescriptorClose = false
        val endpoint = Closeable {
            calls += "endpoint-close"
            check(!failClose)
        }
        val tun = object : RootHotspotEngineOwner.Tun {
            override val input = TunInput(42, 1500) { true }
            override fun close() {
                calls += "tun-close"
                check(!failDescriptorClose)
            }
            override fun verifyClosed() = true
        }
        val handoff = RootHotspotTunHandoff(
            open = { calls += "open"; check(!failOpen); endpoint },
            launch = { calls += "launch"; response },
            receive = { exact, result ->
                assertTrue(exact === endpoint)
                assertEquals(receipt, result)
                calls += "receive"
                check(!failReceive)
                tun
            },
            discard = { calls += "discard"; check(!failDiscard) },
        )
    }

    @Test fun successfulTransferClosesEndpointButRetainsDescriptor() {
        val f = Fixture()
        assertTrue(f.handoff.acquire(session) === f.tun)
        assertEquals(listOf("open", "launch", "receive", "endpoint-close", "discard"), f.calls)
        assertThrows(IllegalStateException::class.java) { f.handoff.acquire(session) }
    }

    @Test fun missingReceiptNeverAcceptsSocket() {
        val f = Fixture()
        f.response = null
        assertThrows(IllegalStateException::class.java) { f.handoff.acquire(session) }
        assertEquals(listOf("open", "launch", "endpoint-close", "discard"), f.calls)
    }

    @Test fun foreignReceiptNeverAcceptsSocket() {
        val f = Fixture()
        f.response = receipt.copy(identity = receipt.identity.copy(session = session.copy(generation = 10)))
        assertThrows(IllegalStateException::class.java) { f.handoff.acquire(session) }
        assertEquals(listOf("open", "launch", "endpoint-close", "discard"), f.calls)
    }

    @Test fun openFailureStillDiscardsStage() {
        val f = Fixture()
        f.failOpen = true
        assertThrows(IllegalStateException::class.java) { f.handoff.acquire(session) }
        assertEquals(listOf("open", "discard"), f.calls)
    }

    @Test fun receiveFailureClosesEndpointAndDiscardsStage() {
        val f = Fixture()
        f.failReceive = true
        assertThrows(IllegalStateException::class.java) { f.handoff.acquire(session) }
        assertEquals(listOf("open", "launch", "receive", "endpoint-close", "discard"), f.calls)
    }

    @Test fun endpointCloseFailureClosesAlreadyReceivedDescriptor() {
        val f = Fixture()
        f.failClose = true
        assertThrows(IllegalStateException::class.java) { f.handoff.acquire(session) }
        assertEquals(listOf("open", "launch", "receive", "endpoint-close", "tun-close", "discard"), f.calls)
    }

    @Test fun primaryFailurePreservedWithSuppressedCleanupFailures() {
        val f = Fixture()
        f.failClose = true
        f.failDescriptorClose = true
        f.failDiscard = true
        val error = assertThrows(IllegalStateException::class.java) { f.handoff.acquire(session) }
        assertEquals(2, error.suppressed.size)
    }
}
