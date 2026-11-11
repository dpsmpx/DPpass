package com.dpsmpx.dppass.desktop

import com.dpsmpx.dppass.diagnostics.DiagCode
import com.dpsmpx.dppass.diagnostics.Outcome
import com.dpsmpx.dppass.engine.SystemTun
import com.dpsmpx.dppass.engine.TunInput
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.awaitCancellation
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNull
import kotlin.test.assertSame
import kotlin.test.assertTrue
import kotlin.test.fail

/** Настоящая смена диспетчера и отмена во время блокирующего подъёма, без системного TUN (аудит R-01). */
class PendingTunnelTest {
    private class Handle : DesktopTunnel {
        override val tunInput: TunInput? = null
        override val systemTun: SystemTun? = null
        val closes = AtomicInteger()
        override fun close() { closes.incrementAndGet() }
    }

    @Test
    fun cancellationDuringBlockingEstablishClosesCreatedHandle() = runBlocking {
        val entered = CountDownLatch(1)
        val release = CountDownLatch(1)
        val handle = Handle()
        val job = launch {
            val pending = PendingTunnel()
            try {
                pending.acquire {
                    entered.countDown()
                    check(release.await(5, TimeUnit.SECONDS)) { "тест не отпустил подъём TUN" }
                    Outcome.Success(handle)
                }
                currentCoroutineContext().ensureActive()
                fail("отменённое подключение не должно продолжиться")
            } finally {
                pending.closeUnclaimed()
            }
        }
        try {
            assertTrue(withContext(Dispatchers.IO) { entered.await(5, TimeUnit.SECONDS) })
            job.cancel()
        } finally {
            release.countDown()
        }
        job.join()
        assertTrue(job.isCancelled)
        assertEquals(1, handle.closes.get())
    }

    @Test
    fun cancellationAfterAcquisitionStillExecutesCleanup() = runBlocking {
        val acquired = CompletableDeferred<Unit>()
        val handle = Handle()
        val job = launch {
            val pending = PendingTunnel()
            try {
                pending.acquire { Outcome.Success(handle) }
                acquired.complete(Unit)
                awaitCancellation()
            } finally {
                pending.closeUnclaimed()
            }
        }
        acquired.await()
        job.cancelAndJoin()
        assertEquals(1, handle.closes.get())
    }

    @Test
    fun exceptionBeforeHandoffClosesOnce() = runBlocking {
        val pending = PendingTunnel()
        val handle = Handle()
        try {
            try {
                pending.acquire { Outcome.Success(handle) }
                error("ошибка подключения после подъёма")
            } finally {
                pending.closeUnclaimed()
            }
        } catch (e: IllegalStateException) {
            assertEquals("ошибка подключения после подъёма", e.message)
        }
        pending.closeUnclaimed()
        assertEquals(1, handle.closes.get())
    }

    @Test
    fun declinedConnectionClosesWithoutCancellation() = runBlocking {
        val pending = PendingTunnel()
        val handle = Handle()
        try {
            pending.acquire { Outcome.Success(handle) }
            // Отказ плана или отсутствие кандидатов: владение сеансу не передано.
        } finally {
            pending.closeUnclaimed()
        }
        assertEquals(1, handle.closes.get())
    }

    @Test
    fun successfulHandoffLeavesClosingToSession() = runBlocking {
        val pending = PendingTunnel()
        val handle = Handle()
        try {
            pending.acquire { Outcome.Success(handle) }
            assertSame(handle, pending.take())
        } finally {
            pending.closeUnclaimed()
        }
        assertEquals(0, handle.closes.get())
        assertNull(pending.take())
        handle.close()
        assertEquals(1, handle.closes.get())
    }

    @Test
    fun failedEstablishHasNothingToClose() = runBlocking {
        val pending = PendingTunnel()
        try {
            assertIs<Outcome.Failure>(pending.acquire { Outcome.failure(DiagCode.CAPABILITY_FEATURE_UNSUPPORTED, "нет TUN") })
        } finally {
            pending.closeUnclaimed()
        }
        assertNull(pending.take())
    }
}
