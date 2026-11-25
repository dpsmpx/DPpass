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
        assertTrue(result.exceptionOrNull() === expected)
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
