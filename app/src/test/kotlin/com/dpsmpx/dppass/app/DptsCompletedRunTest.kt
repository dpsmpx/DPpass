package com.dpsmpx.dppass.app

import com.dpsmpx.dppass.engine.xray.DptsScript
import com.dpsmpx.dppass.engine.xray.Zapret2GoogleAttempt
import com.dpsmpx.dppass.engine.xray.Zapret2GoogleProbe
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class DptsCompletedRunTest {
    @Test fun evidenceIsBoundToSourceSessionAndCompleteRows() {
        val source = "dpts 1\nhost www.youtube.com\nhttps ips=1 attempts=1"
        val plan = DptsScript.compile(source)
        val prepared = Zapret2GoogleProbe("dns_ready", 200, 0, 10, 0, 0, "abcdef12", 1)
        val spec = plan.probes.single()
        val row = Zapret2GoogleAttempt(spec.method, spec.attempt,
            Zapret2GoogleProbe("ok", 200, 256, 10, 0, 0, "abcdef12", 1,
                spec.ipIndex, spec.wireProtocol, "tls_verified", "http/1.1"), spec.target)
        val rows = mutableListOf(row)
        val run = DptsCompletedRun.capture(source, plan, prepared, rows, DptsSession.capture("MOBILE", 10L, 20L))
        assertNotNull(run)
        val captured = requireNotNull(run)
        assertTrue(captured.matches(source, DptsSession.capture("MOBILE", 10L, 20L)))
        assertTrue(captured.trainingNetworkSupported)
        for (network in listOf("WIFI", "OTHER", "UNKNOWN")) {
            val other = requireNotNull(DptsCompletedRun.capture(source, plan, prepared,
                rows, DptsSession.capture(network, 10L, 20L)))
            assertTrue(other.matches(source, DptsSession.capture(network, 10L, 20L)))
            assertTrue(other.trainingNetworkSupported == (network == "WIFI"))
        }
        assertFalse(captured.matches(source + "\n# edit", DptsSession.capture("MOBILE", 10L, 20L)))
        assertFalse(captured.matches(source, DptsSession.capture("WIFI", 10L, 20L)))
        assertFalse(captured.matches(source, DptsSession.capture("MOBILE", 11L, 20L)))
        assertFalse(captured.matches(source, DptsSession.capture("MOBILE", 10L, 21L)))
        assertFalse(captured.matches(source, DptsSession.capture("MOBILE", null, 20L)))
        assertFalse(captured.matches(source, DptsSession.capture("MOBILE", 10L, null)))
        rows.clear()
        assertTrue(captured.rows.size == 1)
        assertNull(DptsCompletedRun.capture(source, plan, prepared, rows, DptsSession.capture("MOBILE", 10L, 20L)))
        assertNull(DptsCompletedRun.capture(source, plan, prepared, listOf(row), DptsSession.capture("MOBILE", 10L, -1L)))
    }
}
