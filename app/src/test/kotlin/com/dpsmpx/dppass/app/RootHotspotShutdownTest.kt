package com.dpsmpx.dppass.app

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertSame
import org.junit.jupiter.api.Test

class RootHotspotShutdownTest {
    @Test fun protectionIsRetiredOnlyAfterVerifiedShutdown() {
        for (egress in listOf(false, true)) for (ap in listOf(false, true)) {
            val calls = mutableListOf<String>()
            val result = RootHotspotShutdown.run(
                { calls += "egress"; egress }, { calls += "ap"; ap }, { calls += "guards"; true },
            )
            assertEquals(listOf("egress", "ap") + if (egress && ap) listOf("guards") else emptyList(), calls)
            assertEquals(when {
                !ap -> RootHotspotShutdown.Result.GUARD_RETAINED
                !egress -> RootHotspotShutdown.Result.CLEANUP_PENDING
                else -> RootHotspotShutdown.Result.STOPPED
            }, result)
        }
        assertEquals(RootHotspotShutdown.Result.CLEANUP_PENDING, RootHotspotShutdown.run({ true }, { true }, { false }))
    }

    @Test fun egressExceptionStillClosesAccessPointButKeepsGuards() {
        var closed = false
        assertThrows(IllegalStateException::class.java) {
            RootHotspotShutdown.run({ error("stop failed") }, { closed = true; true }, { throw AssertionError() })
        }
        assertEquals(true, closed)
    }

    @Test fun doubleFailurePreservesOriginalAndNeverRetiresGuards() {
        val original = IllegalStateException("egress failed")
        val secondary = IllegalStateException("AP failed")
        val caught = assertThrows(IllegalStateException::class.java) {
            RootHotspotShutdown.run({ throw original }, { throw secondary }, { error("must not retire") })
        }
        assertSame(original, caught)
        assertSame(secondary, caught.suppressed.single())
    }

    @Test fun unconfirmedAccessPointClosureIsRecordedAfterEgressFailure() {
        val original = IllegalStateException("egress failed")
        val caught = assertThrows(IllegalStateException::class.java) {
            RootHotspotShutdown.run({ throw original }, { false }, { error("must not retire") })
        }
        assertSame(original, caught)
        assertEquals("ROOT hotspot AP shutdown unconfirmed", caught.suppressed.single().message)
    }

    @Test fun rethrowingSameFailureDoesNotAttemptSelfSuppression() {
        val original = IllegalStateException("stop failed")
        val caught = assertThrows(IllegalStateException::class.java) {
            RootHotspotShutdown.run({ throw original }, { throw original }, { error("must not retire") })
        }
        assertSame(original, caught)
        assertEquals(0, caught.suppressed.size)
    }
}
