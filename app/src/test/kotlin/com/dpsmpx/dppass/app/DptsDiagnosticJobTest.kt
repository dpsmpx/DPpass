package com.dpsmpx.dppass.app

import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeout
import kotlinx.coroutines.yield
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class DptsDiagnosticJobTest {
    @Test fun cancellationRetainsSlotUntilBlockingWorkActuallyFinishes() = runBlocking {
        val entered = CompletableDeferred<Unit>()
        val release = CompletableDeferred<Unit>()
        var secondRan = false
        val slot = DptsDiagnosticJob(this) {}
        try {
            assertTrue(slot.start {
                withContext(NonCancellable) {
                    entered.complete(Unit)
                    release.await()
                }
            })
            withTimeout(5000) { entered.await() }
            assertTrue(slot.busy)
            slot.cancel()
            assertTrue(slot.busy)
            assertFalse(slot.cancellable)
            assertFalse(slot.start { secondRan = true })
            assertFalse(secondRan)
        } finally {
            release.complete(Unit)
        }
        withTimeout(5000) { while (slot.busy) yield() }
        assertTrue(slot.start { secondRan = true })
        withTimeout(5000) { while (slot.busy) yield() }
        assertTrue(secondRan)
    }

    @Test fun immediateCompletionReleasesTheSlot() = runBlocking {
        var notifications = 0
        val slot = DptsDiagnosticJob(this) { notifications++ }
        assertTrue(slot.start {})
        withTimeout(5000) { while (slot.busy) yield() }
        assertTrue(notifications >= 2)
        assertFalse(slot.cancellable)
    }
}
