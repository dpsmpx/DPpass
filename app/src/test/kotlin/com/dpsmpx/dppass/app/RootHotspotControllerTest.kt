package com.dpsmpx.dppass.app

import java.io.File
import java.nio.file.Files
import java.util.UUID
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class RootHotspotControllerTest {
    private class Resource
    private val request = RootHotspotLifecycle.Request(9, RootHotspotAdmission.Mode.VPN)
    private val session = RootHotspotAdmission.Session(9, 12, request.mode)
    private val identity = RootHotspotInterfaceEvidence.Identity(session, "wlan1", "192.168.43.1")
    private fun evidence() = RootHotspotAdmission.Evidence(true, session, session, session, session, session, session)
    private fun run(script: String) = RootCommandRunner.run(listOf("/bin/sh", "-c",
        RootHotspotNetworkFixture.clean + script), 10_000).exitCode == 0

    private fun fixture(test: (File, RootHotspotClaim) -> Unit) {
        if (!File("/bin/sh").canExecute() || !run("command -v flock >/dev/null")) return
        val dir = Files.createTempDirectory("dppass-hotspot-controller").toFile()
        try {
            val owner = RootHotspotOwner(
                RootOwnerIdentity(ProcessHandle.current().pid().toInt(), RootProcessIdentity.currentAppStartTime()),
                UUID.fromString(File("/proc/sys/kernel/random/boot_id").readText().trim()),
            )
            test(dir, RootHotspotClaim.pending(request.generation, request.mode, owner,
                RootHotspotNetworkFixture.slot, dir.path, adapterDirectories = emptyList()))
        } finally { dir.deleteRecursively() }
    }

    @Test fun completeSessionReservesBindsAndRetiresInOrder() = fixture { dir, claim ->
        val calls = mutableListOf<String>()
        val controller = RootHotspotController<Resource>({ calls += "release" }, ::run)
        val marker = File(dir, "hotspot.owner")
        assertEquals(RootHotspotLifecycle.StartResult.READY, controller.start(request, claim, 1000,
            dispatch = {
                assertTrue(marker.exists())
                assertEquals(request, controller.snapshot().request)
                assertEquals(null, controller.snapshot().session)
                calls += "dispatch"; it.started(Resource())
            },
            discover = { calls += "discover"; identity },
            prepare = { _, _, owned ->
                assertEquals(session, controller.snapshot().session)
                assertTrue(owned(":")); calls += "prepare"; evidence()
            },
            attach = { _, owned -> calls += "attach"; owned(":") },
            stopEgress = { _, owned -> calls += "egress"; owned(":") },
            verifyStopped = { calls += "verify"; true },
            cleanup = { calls += "cleanup"; ":" },
        ))
        assertEquals(listOf("dispatch", "discover", "prepare", "attach"), calls)
        assertEquals(RootHotspotLifecycle.StopResult.STALE, controller.stop(request.copy(generation = 10)))
        assertEquals(RootHotspotLifecycle.StopResult.STOPPED, controller.stop(request))
        assertEquals(listOf("dispatch", "discover", "prepare", "attach", "egress", "release", "verify", "cleanup", "verify"), calls)
        assertFalse(marker.exists())
    }

    @Test fun cancelledPendingRequestNeverPreparesOrAttaches() = fixture { dir, claim ->
        val controller = RootHotspotController<Resource>({}, ::run)
        assertEquals(RootHotspotLifecycle.StartResult.CANCELLED, controller.start(request, claim, 1000,
            dispatch = {
                assertEquals(RootHotspotLifecycle.StopResult.CANCEL_REQUESTED, controller.stop(request))
                it.started(Resource())
            },
            discover = { identity },
            prepare = { _, _, _ -> error("cancelled") },
            attach = { _, _ -> error("cancelled") },
            stopEgress = { _, _ -> error("not prepared") },
            verifyStopped = { true },
            cleanup = { error("not prepared") },
        ))
        assertFalse(File(dir, "hotspot.owner").exists())
    }

    @Test fun unknownIdentityRetainsClaimUntilRequestRetired() = fixture { dir, claim ->
        var stopped = false
        val controller = RootHotspotController<Resource>({}, ::run)
        assertEquals(RootHotspotLifecycle.StartResult.CLEANUP_PENDING, controller.start(request, claim, 1000,
            dispatch = { it.started(Resource()) }, discover = { null },
            prepare = { _, _, _ -> error("unknown interface") },
            attach = { _, _ -> error("unknown interface") },
            stopEgress = { _, _ -> error("not prepared") },
            verifyStopped = { stopped }, cleanup = { error("not prepared") },
        ))
        assertTrue(File(dir, "hotspot.owner").exists())
        assertEquals(RootHotspotLifecycle.StopResult.CLEANUP_PENDING, controller.stop(request))
        stopped = true
        assertEquals(RootHotspotLifecycle.StopResult.STOPPED, controller.stop(request))
        assertFalse(File(dir, "hotspot.owner").exists())
    }

    @Test fun failedAcquisitionDoesNotDispatchAndRetainsLocalOwner() = fixture { _, claim ->
        val controller = RootHotspotController<Resource>({}, { false })
        assertEquals(RootHotspotLifecycle.StartResult.CLEANUP_PENDING, controller.start(request, claim, 1000,
            dispatch = { error("not reserved") }, discover = { error("not reserved") },
            prepare = { _, _, _ -> error("not reserved") }, attach = { _, _ -> error("not reserved") },
            stopEgress = { _, _ -> error("not prepared") }, verifyStopped = { true },
            cleanup = { error("not prepared") },
        ))
        assertEquals(RootHotspotLifecycle.State.CLEANUP_PENDING, controller.snapshot().state)
    }

    @Test fun admissionFailureRetainsGuardsUntilPlatformStops() = fixture { dir, claim ->
        var stopped = false
        var retired = 0
        val controller = RootHotspotController<Resource>({}, ::run)
        assertEquals(RootHotspotLifecycle.StartResult.CLEANUP_PENDING, controller.start(request, claim, 1000,
            dispatch = { it.started(Resource()) }, discover = { identity },
            prepare = { _, _, _ -> evidence().copy(noOffloadBypass = null) },
            attach = { _, _ -> error("not admitted") },
            stopEgress = { _, _ -> true }, verifyStopped = { stopped },
            cleanup = { retired++; ":" },
        ))
        assertEquals(0, retired)
        assertTrue(File(dir, "hotspot.owner").exists())
        stopped = true
        assertEquals(RootHotspotLifecycle.StopResult.STOPPED, controller.stop(request))
        assertEquals(1, retired)
    }
}
