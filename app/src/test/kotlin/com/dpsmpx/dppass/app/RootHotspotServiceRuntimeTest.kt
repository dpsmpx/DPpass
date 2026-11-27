package com.dpsmpx.dppass.app

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Test

class RootHotspotServiceRuntimeTest {
    private class Resource
    private val request = RootHotspotLifecycle.Request(9, RootHotspotAdmission.Mode.VPN)
    private val session = RootHotspotAdmission.Session(9, 12, request.mode)
    private val identity = RootHotspotInterfaceEvidence.Identity(session, "wlan1", "192.168.43.1")

    private inner class Fixture {
        var initialized = true
        var baseline = true
        var inspection = "absent\n"
        var boot = "11111111-2222-3333-4444-555555555555\n"
        var mutate = true
        var calls = mutableListOf<String>()
        val root = RootHotspotRootAccess({ args, _ ->
            val script = args.last()
            val result = when {
                "environment_ready" in script -> { calls += "initialize"; if (initialized) "environment_ready\n" else "" }
                "baseline_available" in script -> { calls += "baseline"; if (baseline) "baseline_available\n" else "" }
                "printf 'present" in script -> { calls += "inspect"; inspection }
                "cat /proc/sys/kernel/random/boot_id" in script -> { calls += "boot"; boot }
                else -> { calls += "mutation"; "" }
            }
            RootCommandRunner.CompleteResult(if (!mutate && calls.last() == "mutation") 1 else 0, result)
        })
        val ap = object : RootHotspotServiceRuntime.AccessPoint<Resource> {
            override fun dispatch(pending: RootHotspotReservation<Resource>) {
                calls += "dispatch"
                pending.started(Resource())
            }
            override fun release(resource: Resource) { calls += "release" }
            override fun discover(resource: Resource) = identity
            override fun verifyStopped(identity: RootHotspotInterfaceEvidence.Identity?) = true
        }
        val egress = object : RootHotspotServiceRuntime.Egress<Resource> {
            override fun prepare(resource: Resource, identity: RootHotspotInterfaceEvidence.Identity,
                                 owned: (String) -> Boolean): RootHotspotAdmission.Evidence {
                calls += "prepare"
                return RootHotspotAdmission.Evidence(true, session, session, session, session, session, session)
            }
            override fun attach(identity: RootHotspotInterfaceEvidence.Identity, owned: (String) -> Boolean): Boolean {
                calls += "attach"
                return owned(":")
            }
            override fun stop(identity: RootHotspotInterfaceEvidence.Identity?, owned: (String) -> Boolean): Boolean {
                calls += "stop"
                return owned(":")
            }
            override fun cleanup(identity: RootHotspotInterfaceEvidence.Identity) = ":"
        }
        val runtime = RootHotspotServiceRuntime(request, root, { RootOwnerIdentity(123, "456") },
            RootHotspotNetworkFixture.slot, ap, egress)
    }

    @Test fun constructionDoesNotTouchRootOrPlatform() {
        val f = Fixture()
        assertEquals(emptyList<String>(), f.calls)
        assertEquals(RootHotspotLifecycle.State.IDLE, f.runtime.snapshot().state)
    }

    @Test fun preflightFailureDoesNotDispatchOrMutateClaim() {
        val f = Fixture()
        f.initialized = false
        assertEquals(RootHotspotLifecycle.StartResult.REFUSED, f.runtime.start())
        assertEquals(listOf("initialize"), f.calls)
        assertThrows(IllegalStateException::class.java) { f.runtime.start() }
        val other = Fixture()
        other.baseline = false
        assertEquals(RootHotspotLifecycle.StartResult.REFUSED, other.runtime.start())
        assertEquals(listOf("initialize", "baseline"), other.calls)
    }

    @Test fun unknownOrPresentClaimBlocksBeforeOwnerAndDispatch() {
        for (raw in listOf("", "present\nmalformed\n")) {
            val f = Fixture()
            f.inspection = raw
            assertEquals(RootHotspotLifecycle.StartResult.REFUSED, f.runtime.start())
            assertEquals(listOf("initialize", "baseline", "inspect"), f.calls)
        }
    }

    @Test fun invalidBootIdRefusesBeforeClaimMutation() {
        val f = Fixture()
        f.boot = "unknown\n"
        assertEquals(RootHotspotLifecycle.StartResult.REFUSED, f.runtime.start())
        assertEquals(listOf("initialize", "baseline", "inspect", "boot"), f.calls)
    }

    @Test fun failedClaimAcquisitionRetainsControllerOwnerWithoutDispatch() {
        val f = Fixture()
        f.mutate = false
        assertEquals(RootHotspotLifecycle.StartResult.CLEANUP_PENDING, f.runtime.start())
        assertEquals(RootHotspotLifecycle.State.CLEANUP_PENDING, f.runtime.snapshot().state)
        assertEquals(listOf("initialize", "baseline", "inspect", "boot", "mutation", "mutation"), f.calls)
    }

    @Test fun successfulControllerStartAndStopUseSameRuntime() {
        val f = Fixture()
        assertEquals(RootHotspotLifecycle.StartResult.READY, f.runtime.start())
        assertEquals(session, f.runtime.snapshot().session)
        assertEquals(RootHotspotLifecycle.StopResult.STOPPED, f.runtime.stop())
        assertEquals(RootHotspotLifecycle.State.IDLE, f.runtime.snapshot().state)
        assertEquals(listOf("dispatch", "prepare", "attach", "stop", "release"),
            f.calls.filter { it in setOf("dispatch", "prepare", "attach", "stop", "release") })
    }
}
