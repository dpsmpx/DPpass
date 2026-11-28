package com.dpsmpx.dppass.app

import com.dpsmpx.dppass.engine.xray.DptsInterruption
import com.dpsmpx.dppass.engine.xray.DptsScript
import com.dpsmpx.dppass.engine.xray.Zapret2GoogleAttempt
import com.dpsmpx.dppass.engine.xray.Zapret2GoogleProbe
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Test

class DptsCsvTest {
    private val plan = DptsScript.compile("dpts 1\nname =formula\nhost www.youtube.com\nhttps protocols=h1,h2 methods=plain ips=1 attempts=1")
    private val prep = Zapret2GoogleProbe("dns_ready", 200, 0, 10, 0, 0, "abcdef12", 1)
    private fun row(index: Int, outcome: String = "ok"): Zapret2GoogleAttempt {
        val p = plan.probes[index]
        return Zapret2GoogleAttempt(p.method, p.attempt, Zapret2GoogleProbe(outcome, 200, 256,
            30, 0, 0, "abcdef12", 1, p.ipIndex, p.wireProtocol,
            "tls_verified", if (p.protocol == "h1") "http/1.1" else "h2"), p.target)
    }
    private fun parse(csv: String): List<Map<String, String>> {
        val lines = csv.trimEnd().split("\r\n")
        val header = lines.first().split(",")
        return lines.drop(1).map {
            val values = it.split(",")
            assertEquals(header.size, values.size)
            header.zip(values).toMap()
        }
    }
    @Test fun completedMatrixExportsEveryMatchedRowAndNoTitle() {
        val csv = DptsCsv.render(plan, "WIFI", prep, listOf(row(0), row(1)))
        assertFalse(csv.contains("=formula"))
        val rows = parse(csv)
        assertEquals(2, rows.size)
        assertEquals(listOf("h1", "h2"), rows.map { it["protocol"] })
        assertEquals(listOf("complete", "complete"), rows.map { it["run_state"] })
        assertEquals(listOf("true", "true"), rows.map { it["content_verified"] })
    }
    @Test fun interruptedMatrixPreservesMissingDenominator() {
        val rows = parse(DptsCsv.render(plan, "MOBILE", prep, listOf(row(0)), DptsInterruption.USER_STOP))
        assertEquals(listOf("matched", "missing"), rows.map { it["binding"] })
        assertEquals("interrupted", rows[1]["run_state"])
        assertEquals("user_stop", rows[1]["interruption"])
        assertEquals("", rows[1]["elapsed_ms"])
        assertEquals("", rows[1]["transport_verified"])
    }
    @Test fun wrongBindingAndUntrustedTextDoNotBecomeMeasurementsOrFormulas() {
        val rows = parse(DptsCsv.render(plan, "=formula", prep, listOf(row(1), row(1, "=formula"))))
        assertEquals("incomplete", rows[0]["run_state"])
        assertEquals("unbound", rows[0]["binding"])
        assertEquals("", rows[0]["http_status"])
        assertEquals("", rows[0]["network"])
        assertEquals("", rows[1]["outcome"])
    }
}
