package com.dpsmpx.dppass.app

import com.dpsmpx.dppass.app.RootHotspotAdmission.Evidence
import com.dpsmpx.dppass.app.RootHotspotAdmission.Mode
import com.dpsmpx.dppass.app.RootHotspotAdmission.Session
import com.dpsmpx.dppass.app.RootHotspotLifecycle.StartResult
import com.dpsmpx.dppass.app.RootHotspotLifecycle.State
import com.dpsmpx.dppass.app.RootHotspotLifecycle.StopResult
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertSame
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Test
import java.util.concurrent.TimeoutException

class RootHotspotSessionRunnerTest {
    private class Reservation

    private fun session(generation: Long = 1) = Session(generation, 2, Mode.VPN)
    private fun evidence(session: Session) = Evidence(true, session, session, session, session, session, session)

    @Test fun orderedStartupAndShutdownUseExactReservation() {
        val calls = mutableListOf<String>()
        val resource = Reservation()
        val session = session()
        val runner = RootHotspotSessionRunner<Reservation> {
            assertSame(resource, it)
            calls += "release"
        }
        assertEquals(StartResult.READY, runner.start(session, 1000,
            request = { calls += "request"; it.started(resource) },
            prepare = { assertSame(resource, it); calls += "prepare"; evidence(session) },
            attach = { assertSame(resource, it); calls += "attach"; true },
            stopEgress = { calls += "egress"; true },
            verifyStopped = { calls += "verify"; true },
            retireGuards = { calls += "guards"; true },
        ))
        assertEquals(listOf("request", "prepare", "attach"), calls)
        assertEquals(StopResult.STOPPED, runner.stop(session))
        assertEquals(listOf("request", "prepare", "attach", "egress", "release", "verify", "guards"), calls)
        assertEquals(State.IDLE, runner.snapshot().state)
    }

    @Test fun admissionRefusalAndUnconfirmedPlatformStopRetainGuards() {
        val session = session()
        val calls = mutableListOf<String>()
        var stopped = false
        val runner = RootHotspotSessionRunner<Reservation> { calls += "release" }
        assertEquals(StartResult.CLEANUP_PENDING, runner.start(session, 1000,
            request = { it.started(Reservation()) },
            prepare = { evidence(session).copy(noOffloadBypass = null) },
            attach = { error("must not attach") },
            stopEgress = { calls += "egress"; true },
            verifyStopped = { calls += "verify"; stopped },
            retireGuards = { calls += "guards"; true },
        ))
        assertEquals(listOf("egress", "release", "verify"), calls)
        assertEquals(State.CLEANUP_PENDING, runner.snapshot().state)
        stopped = true
        assertEquals(StopResult.STOPPED, runner.stop(session))
        assertEquals(listOf("egress", "release", "verify", "egress", "verify", "guards"), calls)
    }

    @Test fun failedTakenReleaseIsRetriedWithoutDroppingOwnership() {
        val session = session()
        val resource = Reservation()
        val primary = IllegalStateException("release failed")
        var releases = 0
        var verified = 0
        var retired = 0
        val runner = RootHotspotSessionRunner<Reservation> {
            assertSame(resource, it)
            if (++releases == 1) throw primary
        }
        assertEquals(StartResult.READY, runner.start(session, 1000,
            request = { it.started(resource) },
            prepare = { evidence(session) },
            attach = { true },
            stopEgress = { true },
            verifyStopped = { verified++; true },
            retireGuards = { retired++; true },
        ))
        assertSame(primary, assertThrows(IllegalStateException::class.java) { runner.stop(session) })
        assertEquals(State.CLEANUP_PENDING, runner.snapshot().state)
        assertEquals(0, verified)
        assertEquals(0, retired)
        assertEquals(StopResult.STOPPED, runner.stop(session))
        assertEquals(2, releases)
        assertEquals(1, verified)
        assertEquals(1, retired)
    }

    @Test fun timeoutRetainsPendingRequestAndReleasesLateArrival() {
        val session = session()
        lateinit var pending: RootHotspotReservation<Reservation>
        var releases = 0
        var retired = 0
        var stopped = false
        val runner = RootHotspotSessionRunner<Reservation> { releases++ }
        assertThrows(TimeoutException::class.java) {
            runner.start(session, 1,
                request = { pending = it },
                prepare = { error("no reservation") },
                attach = { error("must not attach") },
                stopEgress = { true },
                verifyStopped = { stopped },
                retireGuards = { retired++; true },
            )
        }
        assertEquals(State.CLEANUP_PENDING, runner.snapshot().state)
        assertEquals(0, retired)
        pending.started(Reservation())
        assertEquals(1, releases)
        stopped = true
        assertEquals(StopResult.STOPPED, runner.stop(session))
        assertEquals(1, retired)
    }

    @Test fun synchronousRequestFailureAfterDeliveryReleasesUntakenResource() {
        val session = session()
        val resource = Reservation()
        val primary = IllegalStateException("request failed")
        var released = 0
        val runner = RootHotspotSessionRunner<Reservation> {
            assertSame(resource, it)
            released++
        }
        assertSame(primary, assertThrows(IllegalStateException::class.java) {
            runner.start(session, 1000,
                request = { it.started(resource); throw primary },
                prepare = { error("must not prepare") },
                attach = { error("must not attach") },
                stopEgress = { true },
                verifyStopped = { true },
                retireGuards = { true },
            )
        })
        assertEquals(1, released)
        assertEquals(State.IDLE, runner.snapshot().state)
    }

    @Test fun cancellationDuringPreparationSkipsAttachAndCleansOwnedResource() {
        val session = session()
        var released = 0
        val runner = RootHotspotSessionRunner<Reservation> { released++ }
        assertEquals(StartResult.CANCELLED, runner.start(session, 1000,
            request = { it.started(Reservation()) },
            prepare = {
                assertEquals(StopResult.CANCEL_REQUESTED, runner.stop(session))
                evidence(session)
            },
            attach = { error("must not attach") },
            stopEgress = { true },
            verifyStopped = { true },
            retireGuards = { true },
        ))
        assertEquals(1, released)
        assertEquals(State.IDLE, runner.snapshot().state)
    }

    @Test fun busyOrStaleRequestDoesNotAcquireAnotherReservation() {
        val session = session()
        val runner = RootHotspotSessionRunner<Reservation> {}
        fun start(request: Session, acquire: (RootHotspotReservation<Reservation>) -> Unit) =
            runner.start(request, 1000, acquire, { evidence(request) }, { true }, { true }, { true }, { true })
        assertEquals(StartResult.READY, start(session) { it.started(Reservation()) })
        assertEquals(StartResult.BUSY, start(session(2)) { error("must not request") })
        assertEquals(StopResult.STOPPED, runner.stop(session))
        assertEquals(StartResult.STALE, start(session) { error("must not request") })
    }
}
