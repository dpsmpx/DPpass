package com.dpsmpx.dppass.app

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertSame
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.TimeoutException
import java.util.concurrent.atomic.AtomicInteger

class RootHotspotReservationTest {
    private class Reservation {
        val releases = AtomicInteger()
        fun release() { releases.incrementAndGet() }
    }

    private fun pending() = RootHotspotReservation<Reservation> { it.release() }

    @Test fun transferIsSingleAndCloseDoesNotReclaimTakenResource() {
        val pending = pending()
        val resource = Reservation()
        pending.started(resource)
        pending.started(resource)
        assertSame(resource, pending.take(1000))
        pending.started(resource)
        pending.failed(IllegalStateException("late stop"))
        pending.close()
        assertEquals(0, resource.releases.get())
        assertThrows(IllegalStateException::class.java) { pending.take(1000) }
        resource.release()
        assertEquals(1, resource.releases.get())
    }

    @Test fun abandonmentReleasesUnclaimedReservation() {
        val pending = pending()
        val resource = Reservation()
        pending.started(resource)
        pending.close()
        pending.close()
        pending.started(resource)
        assertEquals(1, resource.releases.get())
        assertThrows(IllegalStateException::class.java) { pending.take(1000) }
    }

    @Test fun timeoutDiscardsLateArrival() {
        val pending = pending()
        assertThrows(TimeoutException::class.java) { pending.take(1) }
        val resource = Reservation()
        pending.started(resource)
        assertEquals(1, resource.releases.get())
        assertThrows(IllegalStateException::class.java) { pending.take(1000) }
    }

    @Test fun terminalFailureReleasesReadyResourceAndPreservesCause() {
        val pending = pending()
        val resource = Reservation()
        val cause = IllegalStateException("AP stopped")
        pending.started(resource)
        pending.failed(cause)
        pending.close()
        assertSame(cause, assertThrows(IllegalStateException::class.java) { pending.take(1000) })
        assertEquals(1, resource.releases.get())
    }

    @Test fun failureBeforeDeliveryDiscardsLateArrival() {
        val pending = pending()
        val cause = IllegalStateException("AP failed")
        pending.failed(cause)
        val resource = Reservation()
        pending.started(resource)
        assertEquals(1, resource.releases.get())
        assertSame(cause, assertThrows(IllegalStateException::class.java) { pending.take(1000) })
    }

    @Test fun unrelatedExtraResourceIsReleasedWithoutReclaimingAcceptedOne() {
        val pending = pending()
        val first = Reservation()
        val extra = Reservation()
        pending.started(first)
        pending.started(extra)
        assertEquals(1, extra.releases.get())
        assertSame(first, pending.take(1000))
        assertEquals(0, first.releases.get())
        first.release()
    }

    @Test fun concurrentAbandonmentAndDeliveryReleaseExactlyOnce() {
        val pool = Executors.newFixedThreadPool(2)
        try {
            repeat(50) {
                val pending = pending()
                val resource = Reservation()
                val go = CountDownLatch(1)
                val delivery = pool.submit {
                    check(go.await(5, TimeUnit.SECONDS))
                    pending.started(resource)
                }
                val cancellation = pool.submit {
                    check(go.await(5, TimeUnit.SECONDS))
                    pending.close()
                }
                go.countDown()
                delivery.get(5, TimeUnit.SECONDS)
                cancellation.get(5, TimeUnit.SECONDS)
                assertEquals(1, resource.releases.get())
                assertThrows(IllegalStateException::class.java) { pending.take(1000) }
            }
        } finally {
            pool.shutdownNow()
        }
    }

    @Test fun interruptionAbandonsRequestAndRestoresInterrupt() {
        val pending = pending()
        val resource = Reservation()
        val pool = Executors.newSingleThreadExecutor()
        try {
            val interrupted = pool.submit<Boolean> {
                Thread.currentThread().interrupt()
                try {
                    assertThrows(InterruptedException::class.java) { pending.take(1000) }
                    Thread.currentThread().isInterrupted
                } finally {
                    Thread.interrupted()
                }
            }
            assertTrue(interrupted.get(5, TimeUnit.SECONDS))
            pending.started(resource)
            assertEquals(1, resource.releases.get())
        } finally {
            pool.shutdownNow()
        }
    }
}
