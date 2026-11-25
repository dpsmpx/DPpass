package com.dpsmpx.dppass.app

import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.Job
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.job
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class RootDpiRuntimeTest {
    private class Fake(
        private val duringStart: suspend () -> Unit = {},
        private val startResult: Result<Unit> = Result.success(Unit),
        private val stopResult: Result<Unit> = Result.success(Unit),
        private val stopException: Throwable? = null,
    ) : RootDpiRuntime {
        var stops = 0
        override suspend fun start(): Result<Unit> {
            duringStart()
            return startResult
        }
        override suspend fun stop(): Result<Unit> {
            stops++
            stopException?.let { throw it }
            return stopResult
        }
        override suspend fun alive() = true
    }

    @Test fun cleanupSuccessAndReturnedFailureRemainDistinguishable() = runBlocking {
        val good = Fake()
        val bad = Fake(stopResult = Result.failure(IllegalStateException("cleanup failed")))
        assertTrue(good.stopForCleanup().isSuccess)
        assertEquals("cleanup failed", bad.stopForCleanup().exceptionOrNull()?.message)
        assertEquals(1, good.stops)
        assertEquals(1, bad.stops)
    }

    @Test fun cleanupThrownFailureIsReturnedAndCanBeRetried() = runBlocking {
        val runtime = Fake(stopException = IllegalStateException("cleanup threw"))
        repeat(2) {
            assertEquals("cleanup threw", runtime.stopForCleanup().exceptionOrNull()?.message)
        }
        assertEquals(2, runtime.stops)
    }

    @Test fun successfulLaunchDoesNotRollBack() {
        var launches = 0
        var rollbacks = 0
        rootLaunchWithRollback({ launches++ }, { rollbacks++ })
        assertEquals(1, launches)
        assertEquals(0, rollbacks)
    }

    @Test fun failedLaunchPreservesErrorAfterSuccessfulRollback() {
        val startup = IllegalStateException("start failed")
        var rollbacks = 0
        val result = runCatching {
            rootLaunchWithRollback({ throw startup }, { rollbacks++ })
        }
        assertTrue(result.exceptionOrNull() === startup)
        assertEquals(1, rollbacks)
    }

    @Test fun failedLaunchReportsFailedRollbackWithoutLosingOriginalCause() {
        val startup = IllegalStateException("start failed")
        val cleanup = IllegalStateException("cleanup failed")
        val result = runCatching {
            rootLaunchWithRollback({ throw startup }, { throw cleanup })
        }
        val actual = result.exceptionOrNull()
        assertEquals("start failed; ROOT cleanup failed", actual?.message)
        assertTrue(actual?.cause === startup)
        assertEquals(listOf(cleanup), actual?.suppressed?.toList())
    }

    @Test fun declinedOwnershipRollsBackAfterSuccessfulStart() = runBlocking {
        val owner = Job()
        val runtime = Fake(duringStart = { owner.cancel() })
        val result = runtime.startAndAccept({ !owner.isCancelled }, { throw AssertionError(it) })
        assertNull(result)
        assertEquals(1, runtime.stops)
    }

    @Test fun acceptedOwnershipLeavesCleanupToOwner() = runBlocking {
        val runtime = Fake()
        val result = runtime.startAndAccept({ true }, { throw AssertionError(it) })
        assertTrue(result?.isSuccess == true)
        assertEquals(0, runtime.stops)
    }

    @Test fun startFailureDoesNotRegisterOrDuplicateAdapterRollback() = runBlocking {
        val runtime = Fake(startResult = Result.failure(IllegalStateException("start failed")))
        val result = runtime.startAndAccept({ throw AssertionError("unexpected acceptance") }, { throw AssertionError(it) })
        assertTrue(result?.isFailure == true)
        assertEquals(0, runtime.stops)
    }

    @Test fun realCancellationDuringSuspendedStartStillRollsBack() = runBlocking {
        val entered = CompletableDeferred<Unit>()
        val release = CompletableDeferred<Unit>()
        val runtime = Fake(duringStart = {
            entered.complete(Unit)
            release.await()
        })
        val task = launch(start = CoroutineStart.UNDISPATCHED) {
            val owner = currentCoroutineContext().job
            runtime.startAndAccept({ !owner.isCancelled }, { throw AssertionError(it) })
        }
        entered.await()
        task.cancel()
        release.complete(Unit)
        task.join()
        assertTrue(task.isCancelled)
        assertEquals(1, runtime.stops)
    }

    @Test fun acceptanceExceptionStillRollsBack() = runBlocking {
        val runtime = Fake()
        val expected = IllegalStateException("accept failed")
        val result = runCatching {
            runtime.startAndAccept({ throw expected }, { throw AssertionError(it) })
        }
        val actual = result.exceptionOrNull()
        // Coroutine stack-trace recovery may copy the exception at a suspend boundary.
        assertEquals(expected.javaClass, actual?.javaClass)
        assertEquals(expected.message, actual?.message)
        assertEquals(1, runtime.stops)
    }

    @Test fun thrownRollbackExceptionIsReported() = runBlocking {
        val expected = IllegalStateException("stop threw")
        val runtime = Fake(stopException = expected)
        var error: Throwable? = null
        val result = runtime.startAndAccept({ false }, { error = it })
        assertNull(result)
        assertTrue(error === expected)
        assertEquals(1, runtime.stops)
    }

    @Test fun rollbackFailureIsReported() = runBlocking {
        val runtime = Fake(stopResult = Result.failure(IllegalStateException("cleanup failed")))
        var error: Throwable? = null
        val result = runtime.startAndAccept({ false }, { error = it })
        assertNull(result)
        assertNotNull(error)
        assertEquals(1, runtime.stops)
    }
}
