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
        assertTrue(tls.contains("transport=0/1"))
        assertTrue(tls.contains("content_verified=0/1"))
        val mismatch = report("www.youtube.com", "https") { it.copy(target = "unrelated") }
        assertTrue(mismatch.contains("matched_rows=0; unbound_rows=1"))
        assertTrue(mismatch.contains("content_verified=0/1; matched=0/1"))
        assertTrue(mismatch.contains("binding=unbound"))
        val wrongAlpn = report("www.youtube.com", "https") {
            it.copy(result = it.result.copy(alpn = "h2"))
        }
        assertTrue(wrongAlpn.contains("tls_verified=0/1"))
        assertTrue(wrongAlpn.contains("content_verified=0/1"))
        val changedDns = report("www.youtube.com", "https") {
            it.copy(result = it.result.copy(dnsFingerprint = "12345678"))
        }
        assertTrue(changedDns.contains("matched_rows=0; unbound_rows=1"))
        assertTrue(changedDns.contains("complete_evidence=false"))
        val changedCount = report("www.youtube.com", "https") {
            it.copy(result = it.result.copy(dnsAnswers = 2))
        }
        assertTrue(changedCount.contains("content_verified=0/1; matched=0/1"))
        assertTrue(home.contains("complete_evidence=true"))
    }

    @Test fun repeatedNativeAttemptIdentityIsRejectedAtSecondStatement() {
        val header = "dpts 1\nhost youtubei.googleapis.com\n"
        for ((first, second) in listOf(
            "https ips=1 attempts=1" to "https ips=2 attempts=2 timeout_ms=3000",
            "https ips=1 attempts=1" to "sni ips=1 attempts=1",
            "tls versions=12 ips=1 attempts=1" to "tls versions=12 ips=1 attempts=1",
            "quic ips=1 attempts=1" to "quic ips=1 attempts=1",
        )) {
            val failure = assertFailsWith<DptsCompileException> {
                DptsScript.compile(header + first + "\n" + second)
            }
            assertEquals(4, failure.line)
        }
        val distinct = DptsScript.compile(header +
            "https methods=plain ips=1 attempts=1\n" +
            "https methods=tlsrec-split ips=1 attempts=1\n" +
            "https protocols=h2 ips=1 attempts=1")
        assertEquals(3, distinct.probes.size)
    }

    @Test fun incompleteReportUsesPlannedDenominatorAndExplicitMissingOrExtraRows() {
        val plan = DptsScript.compile("dpts 1\nhost www.youtube.com\nhttps ips=2 attempts=1")
        val prepared = Zapret2GoogleProbe("dns_ready", 200, 0, 10, 0, 0, "abcdef12", 2)
        val spec = plan.probes.first()
        val row = Zapret2GoogleAttempt(spec.method, spec.attempt,
            Zapret2GoogleProbe("ok", 200, 256, 10, 0, 0, "abcdef12", 2,
                spec.ipIndex, "h1", "tls_verified", "http/1.1"), spec.target)
        val partial = DptsScript.report(plan, "MOBILE", prepared, listOf(row))
        assertTrue(partial.contains("content_verified=1/2; matched=1/2"))
        assertTrue(partial.contains("missing_rows=1; extra_rows=0"))
        assertTrue(partial.contains("complete_evidence=false"))
        val extra = DptsScript.report(plan, "MOBILE", prepared, listOf(row, row, row))
        assertTrue(extra.contains("missing_rows=0; extra_rows=1"))
        assertTrue(extra.contains("complete_evidence=false"))
    }

    @Test fun preparedDnsSetMustCoverThePlanBeforeEvidenceIsAccepted() {
        val plan = DptsScript.compile("dpts 1\nhost www.youtube.com\nhttps ips=2 attempts=1")
        val valid = Zapret2GoogleProbe("dns_ready", 200, 0, 10, 0, 0, "abcdef12", 2)
        assertTrue(DptsScript.preparationValid(plan, valid))
        for (invalid in listOf(valid.copy(dnsAnswers = 1), valid.copy(dnsAnswers = 9),
            valid.copy(dnsFingerprint = "-"), valid.copy(outcome = "timeout"))) {
            assertFalse(DptsScript.preparationValid(plan, invalid))
            assertFalse(DptsScript.completeEvidence(plan, invalid, emptyList()))
        }
        assertFalse(DptsScript.completeEvidence(plan, valid, emptyList()))
    }

    @Test fun malformedPlanCannotProduceCompleteOrPositiveEvidence() {
        val plan = DptsScript.compile("dpts 1\nhost www.youtube.com\nhttps ips=1 attempts=1")
        val prepared = Zapret2GoogleProbe("dns_ready", 200, 0, 10, 0, 0, "abcdef12", 1)
        val spec = plan.probes.single()
        val row = Zapret2GoogleAttempt(spec.method, spec.attempt,
            Zapret2GoogleProbe("ok", 200, 256, 10, 0, 0, "abcdef12", 1,
                spec.ipIndex, spec.wireProtocol, "tls_verified", "http/1.1"), spec.target)
        assertTrue(DptsScript.completeEvidence(plan, prepared, listOf(row)))
        for (invalid in listOf(plan.copy(budgetMs = 1),
            plan.copy(probes = listOf(spec, spec), budgetMs = plan.budgetMs * 2),
            plan.copy(probes = listOf(spec.copy(timeoutMs = 999)), budgetMs = 999),
            plan.copy(suite = "site_https"))) {
            val rows = List(invalid.probes.size) { row }
            assertFalse(DptsScript.completeEvidence(invalid, prepared, rows))
            val report = DptsScript.report(invalid, "MOBILE", prepared, rows)
            assertTrue(report.contains("probe_plan_valid=false"))
            assertTrue(report.contains("matched_rows=0"))
            assertTrue(report.contains("complete_evidence=false"))
        }
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
        assertEquals(setOf("split-2", "fake-2", "fake-4", "fake-8", "multisplit"), catalog.scriptOnlyStrategies.toSet())
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

    @Test fun multiSplitIsExplicitTcpDiagnosticOnly() {
        val plan = DptsScript.compile("dpts 1\nhost www.google.com\nhttps protocols=h1,h2 methods=multisplit ips=1 attempts=1")
        assertEquals(2, plan.probes.size)
        assertTrue(plan.probes.all { it.method == "multisplit" })
        assertFailsWith<DptsCompileException> {
            DptsScript.compile("dpts 1\nhost www.google.com\nquic methods=multisplit")
        }
        assertFalse("multisplit" in DptsLearning.trainable)
    }

    @Test fun allBundledPresetsCompileToBoundedPublicTargets() {
        assertEquals(20, DptsPresets.scripts.size)
        for ((name, script) in DptsPresets.scripts) {
            val plan = DptsScript.compile(script)
            assertEquals(name.isNotBlank(), plan.title.isNotBlank())
            assertTrue(plan.suite != null || plan.probes.size in 1..DptsScript.MAX_PROBES)
            assertTrue(plan.budgetMs <= DptsScript.MAX_BUDGET_MS)
            if (plan.suite == null) assertTrue(DptsScript.probePlanValid(plan), name)
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
                "local_http_hostcase", "local_tls" -> "example.com"
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

    @Test fun localHttpSuiteCannotBecomeRemoteOrLearningProbe() {
        val plan = DptsScript.compile("dpts 1\nhost example.com\nlearn off\nsuite local_http_hostcase")
        assertEquals("local_http_hostcase", plan.suite)
        assertTrue(plan.probes.isEmpty())
        assertFailsWith<DptsCompileException> {
            DptsScript.compile("dpts 1\nhost example.com\nlearn observe\nsuite local_http_hostcase")
        }
        assertFailsWith<DptsCompileException> {
            DptsScript.compile("dpts 1\nhost example.com\nhttps methods=http-hostcase")
        }
    }

    @Test fun unicodeHostUsesCanonicalPunycode() {
        val p = DptsScript.compile("dpts 1\nhost пример.рф\nhttps ips=1 attempts=1")
        assertEquals("xn--e1afmkfd.xn--p1ai", p.host)
        assertTrue(p.probes.first().target.endsWith(":xn--e1afmkfd.xn--p1ai"))
    }

    @Test fun copiedPlanCannotRelabelNativeTargetOrProtocol() {
        val plan = DptsScript.compile("dpts 1\nhost www.youtube.com\nhttps ips=1 attempts=1")
        val p = plan.probes.single()
        val prepared = Zapret2GoogleProbe("dns_ready", 200, 0, 10, 0, 0, "abcdef12", 8)
        val invalid = listOf(
            plan.copy(host = "example.org"),
            plan.copy(host = "WWW.YOUTUBE.COM"),
            plan.copy(probes = listOf(p.copy(target = "site_script_h1_ip00_a1_:example.org"))),
            plan.copy(probes = listOf(p.copy(protocol = "h2"))),
            plan.copy(probes = listOf(p.copy(phase = "tls"))),
            plan.copy(probes = listOf(p.copy(ipIndex = 1))),
            plan.copy(probes = listOf(p.copy(attempt = 2))),
            plan.copy(probes = listOf(p.copy(method = "auto"))),
            plan.copy(probes = listOf(p.copy(phase = "unknown"))),
        )
        for (bad in invalid) {
            assertFalse(DptsScript.preparationValid(bad, prepared))
            assertTrue(DptsScript.report(bad, "MOBILE", prepared, emptyList()).contains("probe_plan_valid=false"))
        }
    }

    @Test fun methodSummarySeparatesProtocolAndUsesOnlyMatchedVerifiedReplies() {
        val plan = DptsScript.compile("dpts 1\nhost www.youtube.com\nhttps protocols=h1,h2 methods=plain,tlsrec-split ips=1 attempts=2")
        val prepared = Zapret2GoogleProbe("dns_ready", 200, 0, 10, 0, 0, "abcdef12", 1)
        val rows = plan.probes.map { p ->
            val good = p.method != "plain"
            val probe = Zapret2GoogleProbe(if (good) "ok" else "timeout_tls_no_reply",
                if (good) 200 else 0, if (good) 256 else 0,
                if (p.attempt == 1) 100 else 300, 0, 0, "abcdef12", 1, p.ipIndex,
                p.protocol, if (good) "tls_verified" else "clienthello_sent",
                if (!good) "-" else if (p.protocol == "h1") "http/1.1" else "h2")
            Zapret2GoogleAttempt(p.method, p.attempt, probe, p.target)
        }
        fun line(report: String, protocol: String, method: String) =
            report.lineSequence().single { it.startsWith("  phase=https protocol=$protocol method=$method;") }
        val full = DptsScript.report(plan, "MOBILE", prepared, rows)
        assertTrue(line(full, "h1", "plain").contains("transport=0/2"))
        assertTrue(line(full, "h1", "plain").endsWith("verified_reply_median_ms=-"))
        assertTrue(line(full, "h1", "tlsrec-split").contains("content_verified=2/2"))
        assertTrue(line(full, "h1", "tlsrec-split").endsWith("verified_reply_median_ms=200"))
        assertTrue(line(full, "h2", "tlsrec-split").endsWith("verified_reply_median_ms=200"))
        val partial = DptsScript.report(plan, "MOBILE", prepared, rows.take(4))
        assertTrue(line(partial, "h2", "tlsrec-split").contains("matched=1/2"))
        assertTrue(line(partial, "h2", "tlsrec-split").endsWith("verified_reply_median_ms=100"))
        val wrong = rows.map { row -> if (row.strategy == "tlsrec-split")
            row.copy(result = row.result.copy(dnsFingerprint = "12345678")) else row }
        val mismatch = DptsScript.report(plan, "MOBILE", prepared, wrong)
        assertTrue(line(mismatch, "h1", "tlsrec-split").contains("matched=0/2"))
        assertTrue(line(mismatch, "h1", "tlsrec-split").endsWith("verified_reply_median_ms=-"))
    }

    @Test fun localTlsSuiteIsFixedAndCannotTrain() {
        val source = "dpts 1\nhost example.com\nlearn off\nsuite local_tls"
        val plan = DptsScript.compile(source)
        assertEquals("local_tls", plan.suite)
        assertTrue(plan.probes.isEmpty())
        assertFalse(plan.observeLearning)
        assertTrue(DptsLearning.confirmedWinners(plan, emptyList()).isEmpty())
        for (invalid in listOf(source.replace("learn off", "learn observe"),
            source.replace("example.com", "example.org"),
            source + "\nhttps", source + "\nsuite local_http_hostcase")) {
            assertFailsWith<DptsCompileException> { DptsScript.compile(invalid) }
        }
    }

    @Test fun localTlsWireOutcomesAreNotRemoteContentEvidence() {
        for (outcome in listOf("local_tls_verified", "local_tls_mismatch")) {
            val result = Zapret2GoogleProbe.fromWire("v1\t$outcome\t0\t0\t5\t1\t0".encodeToByteArray())
            assertEquals(outcome, result.outcome)
            assertFalse(result.success)
            assertFalse(result.httpReachable)
        }
    }
}
