package com.dpsmpx.dppass.app

import java.util.UUID
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class RootHotspotRootAccessTest {
    private val boot = UUID.fromString("11111111-2222-3333-4444-555555555555")
    private val identity = RootOwnerIdentity(123, "456")
    private val record = RootHotspotOwnerRecord(9, RootHotspotAdmission.Mode.VPN, null,
        UUID.fromString("12345678-1234-1234-1234-123456789abc"),
        RootHotspotOwner(identity, boot), RootHotspotNetworkFixture.slot)

    private fun access(code: Int, output: String) = RootHotspotRootAccess({ _, _ ->
        RootCommandRunner.CompleteResult(code, output)
    })

    @Test fun inventoryUsesFixedRootCommandAndBoundedDeadline() {
        val calls = mutableListOf<List<String>>()
        val access = RootHotspotRootAccess({ args, timeout ->
            assertEquals(1234L, timeout)
            calls += args
            RootCommandRunner.CompleteResult(0, "fixture\n")
        }, 1234)
        assertEquals("fixture\n", access.read(listOf("ip", "-o", "link", "show")).stdout)
        assertEquals(listOf("su", "-c", "test \"\$(id -u)\" = 0 || exit 1\nip -o link show"), calls.single())
        assertThrows(IllegalArgumentException::class.java) {
            access.read(listOf("ip", "route", "flush", "table", "all"))
        }
        assertEquals(1, calls.size)
        assertThrows(IllegalArgumentException::class.java) { RootHotspotRootAccess(timeoutMillis = 0) }
    }

    @Test fun baselineRequiresExactSuccessMarker() {
        assertTrue(access(0, "baseline_available\n").baseline())
        assertFalse(access(1, "baseline_available\n").baseline())
        assertFalse(access(0, "baseline_available").baseline())
        assertFalse(access(0, "warning\nbaseline_available\n").baseline())
    }

    @Test fun ownerRequiresCanonicalCompleteBootId() {
        assertEquals(RootHotspotOwner(identity, boot), access(0, "$boot\n").owner(identity))
        for (raw in listOf("", boot.toString(), "$boot\n\n", "1-1-1-1-1\n", "$boot\nextra")) {
            assertNull(access(0, raw).owner(identity))
        }
        assertNull(access(1, "$boot\n").owner(identity))
    }

    @Test fun inspectionDistinguishesAbsentPresentAndUnknown() {
        assertEquals(RootHotspotRootAccess.ClaimState.Absent, access(0, "absent\n").inspect())
        assertEquals(RootHotspotRootAccess.ClaimState.Present(record),
            access(0, "present\n" + record.line() + "\n").inspect())
        for (raw in listOf("", "absent", "absent\nextra", "present\n", "present\nmalformed\n",
            "present\n" + record.line())) {
            assertEquals(RootHotspotRootAccess.ClaimState.Unknown, access(0, raw).inspect())
        }
        assertEquals(RootHotspotRootAccess.ClaimState.Unknown, access(1, "absent\n").inspect())
    }

    @Test fun exceptionsDoNotBecomeSuccessfulMutationsOrAbsence() {
        val access = RootHotspotRootAccess({ _, _ -> error("unavailable") })
        assertFalse(access.execute(":"))
        assertFalse(access.baseline())
        assertNull(access.owner(identity))
        assertEquals(RootHotspotRootAccess.ClaimState.Unknown, access.inspect())
        assertFalse(access(1, "").execute(":"))
        assertTrue(access(0, "").execute(":"))
    }

    @Test fun interruptionIsPreserved() {
        try {
            val access = RootHotspotRootAccess({ _, _ -> throw InterruptedException() })
            assertEquals(RootHotspotRootAccess.ClaimState.Unknown, access.inspect())
            assertTrue(Thread.currentThread().isInterrupted)
        } finally { Thread.interrupted() }
    }
}
