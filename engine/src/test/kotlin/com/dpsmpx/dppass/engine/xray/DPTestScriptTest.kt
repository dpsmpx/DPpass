package com.dpsmpx.dppass.engine.xray

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import kotlin.test.assertFailsWith

class DPTestScriptTest {
    @Test fun allShippedPresetsCompileWithFiniteBudget() {
        assertEquals(8, DPTestPresets.examples.size)
        for ((name, script) in DPTestPresets.examples) {
            val plan = DPTestScript.parse(script)
            assertTrue(plan.steps in 1..DPTestScript.MAX_PROBES, name)
            assertTrue(plan.budgetMillis <= DPTestScript.MAX_WALL_MS, name)
            assertTrue(plan.scenarios.all { s ->
                s.steps.all { it.nativeTarget.startsWith("dpts_") &&
                    it.nativeTarget.endsWith(":" + s.host) }
            }, name)
        }
    }

    @Test fun tlsAndSNIExperimentCompilesToExactNativeTargets() {
        val p = DPTestScript.parse("""
            dptest 1
            name "Pairwise TLS control"
            scenario youtubei.googleapis.com
            ips 2
            attempts 3
            timeout_ms 5000
            methods plain
            protocols tls12,google-tls12,tls13,google-tls13
            train off
            report redacted+clipboard
        """.trimIndent())
        assertEquals(24, p.steps)
        assertEquals(120_000L, p.budgetMillis)
        val targets = p.scenarios.single().steps.map { it.nativeTarget }
        assertTrue("dpts_t12_ip00_a1_:youtubei.googleapis.com" in targets)
        assertTrue("dpts_g12_ip00_a1_:youtubei.googleapis.com" in targets)
        assertTrue("dpts_t13_ip01_a3_:youtubei.googleapis.com" in targets)
        assertTrue("dpts_g13_ip01_a3_:youtubei.googleapis.com" in targets)
        assertEquals(targets.size, targets.distinct().size)
    }

    @Test fun rejectUnknownInstructionsHostSpoofingAndResourceExhaustion() {
        val prefix = "dptest 1\nscenario youtubei.googleapis.com\n"
        for (bad in listOf(
            "shell su",
            "eval print(1)",
            "import java.io.File",
            "methods nfqws2-lua",
            "methods multisplit",
            "methods oob",
            "methods plain,plain",
            "protocols h1,h1",
            "protocols http-unknown",
            "ips 99",
            "attempts 9",
            "timeout_ms 99999",
            "report unredacted",
            "train verified fake-3",
            "methods plain,split-1,split,tlsrec-split,fake-3,fake-5,disorder\n" +
                "protocols h1,h2,tls12,tls13",
        )) {
            assertFailsWith<IllegalArgumentException>(bad) {
                DPTestScript.parse(prefix + bad)
            }
        }
        for (badHost in listOf(
            "127.0.0.1", "localhost", "router.local", "foo.internal",
            "a.example", "foo.home.arpa", "http://google.com",
            "www.google.com:8080", "abc..def", "foo.onion",
        )) {
            assertFailsWith<IllegalArgumentException>(badHost) {
                DPTestScript.parse("dptest 1\nscenario " + badHost)
            }
        }
        assertFailsWith<IllegalArgumentException> {
            DPTestScript.parse("dptest 1\nscenario www.google.com\n" +
                "protocols h3-browse")
        }
        assertFailsWith<IllegalArgumentException> {
            DPTestScript.parse("dptest 1\nscenario www.google.com\n" +
                "protocols quic1\nmethods split")
        }
        assertFailsWith<IllegalArgumentException> {
            DPTestScript.parse("dptest 1\nscenario www.google.com\n" +
                "ips 8\nattempts 3\nmethods plain,tlsrec-split,fake-5\n" +
                "protocols h1\n")
        }
    }

    @Test fun explicitTrainingIsOptInAndRequiresThreeByThreeH1Evidence() {
        val p = DPTestScript.parse(DPTestPresets.examples.values.last())
        assertEquals("tlsrec-split", p.scenarios.single().trainingMethod)
        val bad = p.source.replace("attempts 3", "attempts 2")
        assertFailsWith<IllegalArgumentException> { DPTestScript.parse(bad) }
        assertFailsWith<IllegalArgumentException> {
            DPTestScript.parse(p.source.replace(
                "methods plain,tlsrec-split", "methods tlsrec-split"))
        }
    }

    @Test fun redactedReportNeverConfusesTransportWithContent() {
        val p = DPTestScript.parse("""
            dptest 1
            scenario youtubei.googleapis.com
            ips 1
            attempts 1
            methods plain
            protocols h1
        """.trimIndent())
        val prep = Zapret2GoogleProbe.fromWire(
            "v3\tdns_ready\t200\t0\t120\t0\t0\t6f706c12\t8\t0\tdns\tnone\t-"
                .encodeToByteArray())
        val result = Zapret2GoogleProbe.fromWire(
            "v3\thttp_reachable\t404\t256\t340\t0\t0\t6f706c12\t8\t0\th1\ttls_verified\thttp/1.1"
                .encodeToByteArray())
        assertTrue(DPTestScript.transport(result))
        assertFalse(DPTestScript.verified(result))
        val rows = listOf(
            DPTestScript.ReportEntry(0, null, prep),
            DPTestScript.ReportEntry(0, p.scenarios.single().steps.single(), result),
        )
        val text = DPTestScript.report(p, "MOBILE", rows, true)
        assertTrue(text.contains("content=0/1 http=1/1"))
        assertTrue(text.contains("AUTO: not_applied"))
        assertFalse(text.contains("8.8.8.8"))
        assertFalse(text.contains("/youtubei/v1/browse"))
    }
}
