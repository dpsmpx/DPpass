package com.dpsmpx.dppass.diagnostics

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class RedactorTest {
    private val r = Redactor()

    @Test
    fun uuidIsRemoved() {
        val out = r.redact("auth failed for 00000000-0000-4000-8000-000000000001 at step 2")
        assertFalse("00000000-0000-4000-8000-000000000001" in out)
        assertTrue(Redactor.UUID_MARK in out)
    }

    @Test
    fun urlKeepsOnlySchemeAndHost() {
        val out = r.redact("fetch https://sub.example.com/api/v1/sub/AbC123token?key=zzz failed")
        assertEquals("fetch https://sub.example.com/<redacted> failed", out)
    }

    @Test
    fun shareLinkUserInfoIsRemoved() {
        val out = r.redact("bad link vless://secret-user@203.0.113.1:443?pbk=AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8#x")
        assertFalse("secret-user" in out)
        assertFalse("AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8" in out)
        assertTrue("203.0.113.1:443" in out)
    }

    @Test
    fun secretPairsAndLongTokensAreRemoved() {
        val out = r.redact("password=hunter2 sid: 0a1b2c3d token AbCdEf0123456789AbCdEf0123")
        assertFalse("hunter2" in out)
        assertFalse("0a1b2c3d" in out)
        assertFalse("AbCdEf0123456789AbCdEf0123" in out)
    }

    @Test
    fun codeNamesSurvive() {
        // длинные слова без цифр — коды диагностики, их не трогаем
        assertEquals("SUBSCRIPTION_NO_USABLE_SERVERS", r.redact("SUBSCRIPTION_NO_USABLE_SERVERS"))
    }

    @Test
    fun strictLevelHidesAddresses() {
        val strict = Redactor(Redactor.Level.STRICT)
        val out = strict.redact("connect 203.0.113.7 and 2001:db8::1 via https://cdn.example.net/x")
        assertFalse("203.0.113.7" in out)
        assertFalse("2001:db8::1" in out)
        assertFalse("cdn.example.net" in out)
    }

    // Журнал устройства 19 октября 2026: в скопированный журнал ушло имя сервера
    // из ошибки Go — в ссылке хост был скрыт, а в тексте после неё нет.
    @Test
    fun strictLevelHidesHostnamesInEngineErrors() {
        val strict = Redactor(Redactor.Level.STRICT)
        val error = "failed to dial to (wss://cdn.example.net/ws) > tls: failed to verify certificate: " +
            "x509: certificate is not valid for any names, but wanted to match cdn.example.net"
        val out = strict.redact(error)
        assertFalse("cdn.example.net" in out, out)
        assertTrue(out.endsWith("wanted to match <host>"), out)
        for (text in listOf(
            "lookup srv.example.org: no such host",
            "lookup srv.example.org on <ip>:53: no such host",
            "x509: certificate is valid for a.example.com, b.example.com, not srv.example.org",
            "dialing TCP to tcp:srv.example.org:443",
            "failed to open connection to udp:srv.example.org:8443",
            "host xn--80ak6aa92e.xn--p1ai: refused",
        )) {
            val redacted = strict.redact(text)
            assertFalse("example" in redacted || "xn--80ak6aa92e" in redacted, redacted)
            assertTrue("<host>" in redacted, redacted)
        }
        // Не имя хоста: тип исключения, класс, версия, профиль, путь пакета Xray.
        for (text in listOf(
            "java.lang.IllegalStateException: boom",
            "at com.dpsmpx.dppass.app.MainActivity.onCreate(MainActivity.kt:42)",
            "DPpass 0.7.25-dev",
            "profile=s1.7ed027eec175",
            "proxy/vless/outbound: failed to find an available destination",
            "geodata_ready set=dlc 63777333b7dd",
        )) {
            assertEquals(text, strict.redact(text))
        }
        assertEquals("lookup srv.example.org: no such host", Redactor().redact("lookup srv.example.org: no such host"), "STANDARD имена оставляет")
    }

    // Журнал устройства 17 октября 2026: в ошибке ядра «dial tcp <ip><ip> connect» —
    // порт с двоеточиями по краям принят за IPv6. Адрес скрыт, порт — нет.
    @Test
    fun strictLevelKeepsPortAfterAddress() {
        val strict = Redactor(Redactor.Level.STRICT)
        assertEquals(
            "dial tcp <ip>:443: connect: connection refused",
            strict.redact("dial tcp 203.0.113.7:443: connect: connection refused"),
        )
        assertEquals("dial tcp [<ip>]:443: connect", strict.redact("dial tcp [2001:db8::1]:443: connect"))
        assertEquals("dest :<ip> and <ip>: done", strict.redact("dest :2001:db8::1 and 2001:db8::2: done"))
        for (address in listOf("::1", "fe80::", "2001:db8:0:0:0:0:0:1", "::ffff:198.51.100.1", "aa:bb:cc:dd:ee:ff")) {
            val out = strict.redact("at $address.")
            assertFalse(address in out, out)
            assertTrue("<ip>" in out, out)
        }
    }
}

class LoggerTest {
    @Test
    fun secretsNeverReachTheSink() {
        val sink = MemoryLogSink()
        val log = Logger("t", sink, { 42L })
        log.info("connect", "id" to Secret("00000000-0000-4000-8000-000000000009"), "url" to "https://s.example.com/tok/abc123def456ghi789jkl", "n" to 3)
        val line = sink.snapshot().single().render()
        assertFalse("00000000-0000-4000-8000-000000000009" in line)
        assertFalse("abc123def456ghi789jkl" in line)
        assertTrue("n=3" in line)
    }

    @Test
    fun safeValuesAreNotTouched() {
        val sink = MemoryLogSink()
        Logger("t", sink, { 0L }).info("x", "step" to Safe("COMPILE_0123456789abcdefghij"))
        assertTrue("COMPILE_0123456789abcdefghij" in sink.snapshot().single().render())
    }

    @Test
    fun diagnosticCausesReachTheLog() {
        // Найдено на устройстве: «не активировано» было в журнале без причины (D-22, D-26).
        val core = Diagnostic(
            DiagCode.BACKEND_REJECTED_CONFIG, "ядро Xray: config",
            error = ErrorSummary("xray", "invalid id 00000000-0000-4000-8000-000000000009"),
        )
        val top = Diagnostic.error(DiagCode.ACTIVATION_REJECTED, "не активировано")
            .withCause(Diagnostic.error(DiagCode.BACKEND_REJECTED_CONFIG, "ядро Xray отвергло конфигурацию").withCause(core))
        val sink = MemoryLogSink()
        Logger("t", sink, { 0L }).diagnostic(top)
        val events = sink.snapshot()
        assertEquals(listOf("diagnostic", "cause", "cause"), events.map { it.event })
        assertEquals(listOf(null, "1", "2"), events.map { it.fields["depth"] })
        assertEquals("xray", events[2].fields["error_type"])
        val text = events.joinToString("\n") { it.render() }
        // Найдено на устройстве 5 октября 2026: у диагностик без пути было «path=null».
        assertFalse("path=" in text, text)
        assertTrue("invalid id" in text, text)
        assertFalse("00000000-0000-4000-8000-000000000009" in text, text)
        val lines = top.renderWithCauses()
        assertEquals(3, lines.size)
        assertTrue(lines[2].startsWith("    ERROR BACKEND_REJECTED_CONFIG") && "[xray: invalid id" in lines[2], lines[2])
    }

    @Test
    fun causeChainIsBounded() {
        var d = Diagnostic.error(DiagCode.INTERNAL_ERROR, "leaf")
        repeat(50) { d = Diagnostic.error(DiagCode.INTERNAL_ERROR, "level $it").withCause(d) }
        val sink = MemoryLogSink(capacity = 1000)
        Logger("t", sink, { 0L }).diagnostic(d)
        assertTrue(sink.snapshot().size <= 1 + 9, "${sink.snapshot().size}")
    }

    @Test
    fun ringBufferIsBounded() {
        val sink = MemoryLogSink(capacity = 3)
        val log = Logger("t", sink, { 0L })
        repeat(10) { log.info("e$it") }
        assertEquals(listOf("e7", "e8", "e9"), sink.snapshot().map { it.event })
    }
}

class OutcomeTest {
    @Test
    fun diagnosticsAccumulateAcrossSteps() {
        val a: Outcome<Int> = Outcome.Success(1, listOf(Diagnostic.warning(DiagCode.RULE_SHADOWED, "w")))
        val b = a.then { Outcome.Success(it + 1, listOf(Diagnostic.info(DiagCode.CIDR_HOST_BITS, "i"))) }
        assertEquals(2, b.valueOrNull())
        assertEquals(2, b.diagnostics.size)
    }

    @Test
    fun failureStopsTheChainAndKeepsEarlierNotes() {
        val a: Outcome<Int> = Outcome.Success(1, listOf(Diagnostic.warning(DiagCode.RULE_SHADOWED, "w")))
        val b = a.then { Outcome.failure(DiagCode.JSON_SYNTAX, "e") }.then { Outcome.Success(it) }
        assertTrue(b is Outcome.Failure)
        assertEquals(listOf(DiagCode.RULE_SHADOWED, DiagCode.JSON_SYNTAX), b.diagnostics.map { it.code })
    }

    @Test
    fun failureWithoutErrorIsRejected() {
        assertFailsWith<IllegalArgumentException> { Outcome.Failure(listOf(Diagnostic.warning(DiagCode.RULE_SHADOWED, "w"))) }
    }

    @Test
    fun secretToStringNeverShowsValue() {
        data class Holder(val s: Secret)
        assertFalse("hunter2" in Holder(Secret("hunter2")).toString())
    }

    @Test
    fun reportRedactsEverythingAgain() {
        val report = DiagnosticReport.Builder("r")
            .section("s", "server" to "203.0.113.5", "link" to "vless://00000000-0000-4000-8000-000000000001@a.example.com:443")
            .diagnostics(listOf(Diagnostic.error(DiagCode.ENDPOINT_UNREACHABLE, "no route to 203.0.113.5")))
            .build().render()
        assertFalse("203.0.113.5" in report)
        assertFalse("00000000-0000-4000-8000-000000000001" in report)
        assertTrue("ENDPOINT_UNREACHABLE" in report)
    }
}
