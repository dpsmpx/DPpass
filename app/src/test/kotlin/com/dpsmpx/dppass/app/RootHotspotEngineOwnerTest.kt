package com.dpsmpx.dppass.app

import com.dpsmpx.dppass.core.ProfileId
import com.dpsmpx.dppass.engine.CompiledConfig
import com.dpsmpx.dppass.engine.TunInput
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class RootHotspotEngineOwnerTest {
    private val config = CompiledConfig("xray", "test", ProfileId("guest"), "{}", "fixture")

    private class Fixture {
        val calls = mutableListOf<String>()
        var reserve = true
        var starts = true
        var stops = true
        var closeFails = false
        var verified = true
        var release = true

        val descriptor = object : RootHotspotEngineOwner.Tun {
            override val input = TunInput(42, 1500) { true }
            override fun close() {
                calls += "close"
                check(!closeFails)
            }
            override fun verifyClosed() = verified.also { calls += "verify" }
        }
        val lease = object : RootHotspotEngineOwner.Lease {
            override fun start(config: CompiledConfig, input: TunInput): Boolean {
                assertEquals(42, input.fd)
                calls += "start"
                return starts
            }
            override fun stop() = stops.also { calls += "stop" }
            override fun releaseAfterTunClosed(verifiedClosed: Boolean): Boolean {
                assertTrue(verifiedClosed)
                calls += "release"
                return release
            }
        }
        val owner = RootHotspotEngineOwner {
            calls += "reserve"
            lease.takeIf { reserve }
        }
        fun acquire(): RootHotspotEngineOwner.Tun {
            calls += "tun"
            return descriptor
        }
    }

    @Test fun reserveBeforeAcquiringTunAndReleaseAfterClosure() {
        val f = Fixture()
        assertTrue(f.owner.start(config, f::acquire))
        assertFalse(f.owner.retired())
        assertTrue(f.owner.stop())
        assertTrue(f.owner.retired())
        assertTrue(f.owner.stop())
        assertEquals(listOf("reserve", "tun", "start", "stop", "close", "verify", "release"), f.calls)
        assertThrows(IllegalStateException::class.java) { f.owner.start(config, f::acquire) }
    }

    @Test fun busyEngineNeverAcquiresTun() {
        val f = Fixture()
        f.reserve = false
        assertFalse(f.owner.start(config, f::acquire))
        assertTrue(f.owner.stop())
        assertTrue(f.owner.retired())
        assertEquals(listOf("reserve"), f.calls)
    }

    @Test fun failedNativeStartStillRequiresConfirmedStopBeforeClose() {
        val f = Fixture()
        f.starts = false
        f.stops = false
        assertFalse(f.owner.start(config, f::acquire))
        assertFalse(f.owner.stop())
        assertFalse(f.owner.retired())
        assertFalse("close" in f.calls)
        f.stops = true
        assertTrue(f.owner.stop())
    }

    @Test fun failedCloseAndVerificationRetainExactLeaseForRetry() {
        val f = Fixture()
        assertTrue(f.owner.start(config, f::acquire))
        f.closeFails = true
        assertThrows(IllegalStateException::class.java) { f.owner.stop() }
        assertFalse(f.owner.retired())
        f.closeFails = false
        f.verified = false
        assertFalse(f.owner.stop())
        f.verified = true
        f.release = false
        assertFalse(f.owner.stop())
        f.release = true
        assertTrue(f.owner.stop())
        assertEquals(1, f.calls.count { it == "stop" })
        assertEquals(2, f.calls.count { it == "close" })
        assertEquals(3, f.calls.count { it == "verify" })
    }

    @Test fun ambiguousTunAcquisitionCannotReleaseEngineReservation() {
        val f = Fixture()
        assertThrows(IllegalStateException::class.java) {
            f.owner.start(config) { error("acquisition failed") }
        }
        assertFalse(f.owner.stop())
        assertFalse(f.owner.retired())
        assertFalse("release" in f.calls)
    }
}
