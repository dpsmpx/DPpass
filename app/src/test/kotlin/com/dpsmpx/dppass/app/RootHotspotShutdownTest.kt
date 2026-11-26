package com.dpsmpx.dppass.app

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertThrows
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
}
