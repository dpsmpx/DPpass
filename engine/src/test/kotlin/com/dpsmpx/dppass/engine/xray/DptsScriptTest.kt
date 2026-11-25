package com.dpsmpx.dppass.engine.xray

import com.dpsmpx.dppass.engine.Zapret2ProbeCatalog
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class DptsScriptTest {
    @Test fun diagnosticsUseOriginalSourceLineNumbers() {
        val source = "# introductory comment\r\n\r\ndpts 1\r\n# host\r\n" +
            "host www.google.com\r\n\r\nhttps attempts=4"
        assertEquals(7, assertFailsWith<DptsCompileException> {
            DptsScript.compile(source)
        }.line)
        assertEquals(3, assertFailsWith<DptsCompileException> {
            DptsScript.compile("# comment\n\ndpts 2\nhost www.google.com\nhttps")
        }.line)
        val tooMany = "dpts 1\n" + List(40) { "\n# comment\nhttps" }.joinToString("\n")
        assertEquals(121, assertFailsWith<DptsCompileException> {
            DptsScript.compile(tooMany)
        }.line)
    }

    @Test fun titlesAcceptUnicodeButRejectUnbalancedQuotesAndHiddenControlCharacters() {
        fun compile(title: String) =
            DptsScript.compile("dpts 1\nname $title\nhost www.google.com\nhttps ips=1 attempts=1")
        assertEquals("Проверка HTTPS", compile("\"Проверка HTTPS\"").title)
        assertEquals("Проверка HTTPS", compile("Проверка HTTPS").title)
        for (title in listOf("\"unclosed", "unopened\"", "\"a\"b\"", "\"\"",
            "a\u007fb", "a\u0085b", "a\u202eb", "a\u2028b", "a\u2029b")) {
            assertEquals(2, assertFailsWith<DptsCompileException> { compile(title) }.line)
        }
    }

    @Test fun reportSeparatesVerifiedHandshakeGenericResponseAndMatchedContent() {
        val prepared = Zapret2GoogleProbe("dns_ready", 200, 0, 10, 0, 0, "abcdef12", 8)
        fun report(host: String, operation: String, alter: (Zapret2GoogleAttempt) -> Zapret2GoogleAttempt = { it }): String {
            val plan = DptsScript.compile("dpts 1\nhost $host\n$operation ips=1 attempts=1")
            val spec = plan.probes.single()
            val protocol = if (spec.protocol == "tls12") "h1" else spec.protocol
            val r = Zapret2GoogleProbe("ok", 200, 256, 10, 0, 0,
                "abcdef12", 8, spec.ipIndex, protocol, "tls_verified",
                if (protocol == "h2") "h2" else "http/1.1")
            return DptsScript.report(plan, "MOBILE", prepared,
                listOf(alter(Zapret2GoogleAttempt(spec.method, spec.attempt, r, spec.target))))
        }
        val generic = report("example.org", "https")
        assertTrue(generic.contains("bounded_http_success=1/1"))
        assertTrue(generic.contains("content_verified=0/1"))
        val home = report("www.youtube.com", "https")
        assertTrue(home.contains("content_verified=1/1"))
        val api = report("youtubei.googleapis.com", "https")
        assertTrue(api.contains("content_verified=0/1"))
        val tls = report("www.youtube.com", "tls versions=12") {
            it.copy(result = it.result.copy(httpStatus = 0, bodyBytes = 0, outcome = "timeout_headers"))
        }
        assertTrue(tls.contains("matched_rows=1; unbound_rows=0"))
        assertTrue(tls.contains("tls_verified=1/1"))
        assertTrue(tls.contains("content_verified=0/1"))
        val mismatch = report("www.youtube.com", "https") { it.copy(target = "unrelated") }
        assertTrue(mismatch.contains("matched_rows=0; unbound_rows=1"))
        assertTrue(mismatch.contains("content_verified=0/0"))
        assertTrue(mismatch.contains("binding=unbound"))
        val wrongAlpn = report("www.youtube.com", "https") {
            it.copy(result = it.result.copy(alpn = "h2"))
        }
        assertTrue(wrongAlpn.contains("tls_verified=0/1"))
        assertTrue(wrongAlpn.contains("content_verified=0/1"))
    }

    @Test fun sharedCatalogPreservesDiagnosticOrderAndCalibrationBoundary() {
        val catalog = Zapret2ProbeCatalog
        assertEquals(listOf("plain", "split-1", "split", "fake-3", "fake-5", "disorder", "tlsrec-split"), catalog.siteTcpMethods)
        assertEquals(listOf("plain", "fake-3", "fake-5"), catalog.siteQuicMethods)
        assertEquals(catalog.siteTcpMethods + "auto", catalog.strategies)
        assertEquals(catalog.siteTcpMethods, Zapret2SiteSearch.tcpMethods)
        assertEquals(catalog.siteQuicMethods, Zapret2SiteSearch.quicMethods)
        assertEquals(catalog.siteTcpMethods.drop(1), DptsLearning.trainable.toList())
        assertEquals(catalog.siteTcpMethods.drop(1), catalog.modelTcpMethods)
        assertEquals(catalog.siteQuicMethods.drop(1) + "pass", catalog.modelQuicMethods)
        assertEquals(catalog.modelTcpMethods.size + catalog.modelQuicMethods.size, catalog.modelOutputs)
        assertEquals("dppass-strategy-mlp-v4:tcp=" + catalog.modelTcpMethods.joinToString(",") +
            ";quic=" + catalog.modelQuicMethods.joinToString(","), catalog.modelFormat)
        assertEquals(setOf("split-2", "fake-2", "fake-4", "fake-8"), catalog.scriptOnlyStrategies.toSet())
        assertEquals(setOf("fake-2", "fake-4", "fake-8"), catalog.scriptOnlyQuicStrategies.toSet())
        for ((kind, methods) in listOf("https" to catalog.scriptTcpMethods, "quic" to catalog.scriptQuicMethods)) {
            for (method in methods) {
                val plan = DptsScript.compile("dpts 1\nhost www.google.com\n$kind methods=$method ips=1 attempts=1")
                assertEquals(method, plan.probes.single().method)
            }
            for (method in listOf("auto", "pass", "root")) {
                assertFailsWith<DptsCompileException> {
                    DptsScript.compile("dpts 1\nhost www.google.com\n$kind methods=$method ips=1 attempts=1")
                }
            }
        }
        assertTrue(catalog.scriptOnlyStrategies.none { it in DptsLearning.trainable })
        assertFalse("plain" in DptsLearning.trainable)
    }

    @Test fun allBundledPresetsCompileToBoundedPublicTargets() {
        assertEquals(18, DptsPresets.scripts.size)
        for ((name, script) in DptsPresets.scripts) {
            val plan = DptsScript.compile(script)
            assertEquals(name.isNotBlank(), plan.title.isNotBlank())
            assertTrue(plan.suite != null || plan.probes.size in 1..DptsScript.MAX_PROBES)
            assertTrue(plan.budgetMs <= DptsScript.MAX_BUDGET_MS)
            assertEquals(plan.host, Zapret2SiteSearch.normalizedHost(plan.host))
            for (probe in plan.probes) {
                assertTrue(probe.target.endsWith(":" + plan.host), name)
                assertTrue(probe.ipIndex in 0..7)
                assertTrue(probe.attempt in 1..3)
                assertTrue(probe.timeoutMs in 1000..12000)
                assertTrue(probe.method in Zapret2SiteSearch.tcpMethods ||
                    probe.method in Zapret2SiteSearch.quicMethods ||
                    probe.method in com.dpsmpx.dppass.engine.Zapret2ProbeCatalog.scriptOnlyStrategies)
            }
        }
    }

    @Test fun neverAllowsExecutableCodeUrlsInternalNamesOrUnboundedTests() {
        val cases = listOf(
            "",
            "dpts 2\nhost youtubei.googleapis.com\nhttps",
            "dpts 1\nhost 127.0.0.1\nhttps",
            "dpts 1\nhost 192.168.1.2\nhttps",
            "dpts 1\nhost localhost\nhttps",
            "dpts 1\nhost router.local\nhttps",
            "dpts 1\nhost https://google.com\nhttps",
            "dpts 1\nhost google.com/x\nhttps",
            "dpts 1\nhost www.google.com\nhttps methods=plain,root",
            "dpts 1\nhost www.google.com\nhttps protocols=h3",
            "dpts 1\nhost www.google.com\nquic methods=split",
            "dpts 1\nhost www.google.com\nhttps methods=plain ips=99",
            "dpts 1\nhost www.google.com\nhttps methods=plain attempts=4",
            "dpts 1\nhost www.google.com\nhttps methods=plain timeout_ms=20000",
            "dpts 1\nhost www.google.com\nhttps methods=plain timeout_ms=5",
            "dpts 1\nhost www.google.com\nhttps methods=plain protocols=h1,h1",
            "dpts 1\nhost www.google.com\nhttps methods=plain methods=fake-5",
            "dpts 1\nhost www.google.com\nhttps headers=Authorization",
            "dpts 1\nhost www.google.com\nrun ls",
            "dpts 1\nhost www.google.com\nsni",
            "dpts 1\nhost www.google.com\ntls compare_google=true",
            "dpts 1\nhost youtubei.googleapis.com\ntls compare_google=true methods=fake-5",
            "dpts 1\nhost youtubei.googleapis.com\nlearn train\nhttps",
            "dpts 1\nhost youtubei.googleapis.com\nhttps ips=8 attempts=3 methods=plain,split-1,split,tlsrec-split,fake-3,fake-5,disorder",
            "dpts 1\nhost youtubei.googleapis.com\nhttps ips=8 attempts=3 timeout_ms=12000",
            "dpts 1\nhost youtubei.googleapis.com\nhttps\nhost www.google.com",
        )
        for (script in cases) {
            assertFailsWith<DptsCompileException>("Unexpectedly accepted: $script") {
                DptsScript.compile(script)
            }
        }
    }

    @Test fun matrixExpandsDeterministicallyAndStaysDiagnosticOnly() {
        val plan = DptsScript.compile("""
            dpts 1
            name Test method matrix
            host youtubei.googleapis.com
            learn observe
            https protocols=h1,h2 methods=plain,fake-5 ips=2 attempts=2 timeout_ms=2500
        """.trimIndent())
        assertEquals(16, plan.probes.size)
        assertEquals(40_000L, plan.budgetMs)
        assertTrue(plan.observeLearning)
        assertEquals("site_script_h1_ip00_a1_:youtubei.googleapis.com",
            plan.probes[0].target)
        assertEquals("site_script_h2_ip01_a2_:youtubei.googleapis.com",
            plan.probes.last().target)
        val report = DptsScript.report(plan, "MOBILE",
            Zapret2GoogleProbe("dns_ready", 200, 0, 10, 0, 0,
                "abcdef12", 8), emptyList())
        assertTrue(report.contains("LEARNING: observations_exported_only"))
        assertTrue(report.contains("AUTO: not_applied"))
        assertFalse(report.contains("8.8.8.8"))
    }

    @Test fun sameIPAndTLSControlsUseNativeFixedSafeGrammar() {
        val sni = DptsScript.compile(DptsPresets.scripts.getValue(
            "YouTube API · SNI on same IP"))
        assertEquals(12, sni.probes.size)
        assertEquals("site_sni_google_ip00_a1_:youtubei.googleapis.com",
            sni.probes[1].target)
        val tls = DptsScript.compile(DptsPresets.scripts.getValue(
            "YouTube API · TLS 1.2 / 1.3"))
        assertEquals(24, tls.probes.size)
        assertTrue(tls.probes.any { it.target.startsWith("site_script_tls12_ip") })
        assertTrue(tls.probes.any { it.target.startsWith("site_tls13_google_ip") })
    }

    @Test fun migratedLegacySuiteIsNotExecutableCode() {
        assertEquals(DptsScript.suites, DptsPresets.scripts.values
            .map { DptsScript.compile(it).suite }.filterNotNull().toSet())
        for (id in DptsScript.suites) {
            val host = when (id) {
                "google_youtube" -> "www.google.com"
                "site_https", "site_quic" -> "example.org"
                else -> "youtubei.googleapis.com"
            }
            val result = DptsScript.compile("dpts 1\nhost $host\nsuite $id")
            assertEquals(id, result.suite)
            assertTrue(result.probes.isEmpty())
            if (id !in setOf("site_https", "site_quic")) {
                val failure = assertFailsWith<DptsCompileException> {
                    DptsScript.compile("dpts 1\nhost example.org\nsuite $id")
                }
                assertEquals(3, failure.line)
                assertTrue(failure.message.orEmpty().contains(host))
            }
        }
        for (script in listOf(
            "dpts 1\nhost youtubei.googleapis.com\nsuite android_exec",
            "dpts 1\nhost www.youtube.com\nsuite h3_api",
            "dpts 1\nhost www.youtube.com\nsuite site_https\nhttps",
            "dpts 1\nhost www.youtube.com\nhttps\nsuite site_https",
            "dpts 1\nhost youtubei.googleapis.com\nsuite tls_versions\nsuite tls_versions",
        )) {
            assertFailsWith<DptsCompileException>(script) {
                DptsScript.compile(script)
            }
        }
    }

    @Test fun unicodeHostUsesCanonicalPunycode() {
        val p = DptsScript.compile("dpts 1\nhost пример.рф\nhttps ips=1 attempts=1")
        assertEquals("xn--e1afmkfd.xn--p1ai", p.host)
        assertTrue(p.probes.first().target.endsWith(":xn--e1afmkfd.xn--p1ai"))
    }
}
