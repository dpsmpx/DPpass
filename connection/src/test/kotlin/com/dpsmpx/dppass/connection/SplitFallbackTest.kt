package com.dpsmpx.dppass.connection

import com.dpsmpx.dppass.core.ManualClock
import com.dpsmpx.dppass.core.ProfileId
import com.dpsmpx.dppass.diagnostics.DiagCode
import com.dpsmpx.dppass.diagnostics.Diagnostic
import com.dpsmpx.dppass.diagnostics.Logger
import com.dpsmpx.dppass.diagnostics.MemoryLogSink
import com.dpsmpx.dppass.diagnostics.Outcome
import com.dpsmpx.dppass.engine.mock.MockBackendCompiler
import com.dpsmpx.dppass.engine.mock.MockProxyEngine
import com.dpsmpx.dppass.engine.xray.DnsProbeOutcome
import com.dpsmpx.dppass.engine.xray.DnsProbeResult
import com.dpsmpx.dppass.engine.xray.XrayHealth
import com.dpsmpx.dppass.routing.DnsRoute
import com.dpsmpx.dppass.routing.DnsServer
import com.dpsmpx.dppass.routing.DnsTransport
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertTrue

/**
 * Сервер, не принявший разбитый ClientHello (D-69, к D-68): та же попытка
 * без разбиения, сервер запоминается; отказ TCP и тайм-аут — не повод.
 */
class SplitFallbackTest {
    private val multi = ir("valid-multi.json")

    private val dns = DnsServer("remote", DnsTransport.Https("https://dns.example.net/dns-query"), DnsRoute.TUNNEL)

    /**
     * Отказ — как его собирает настоящая проба здоровья ([XrayHealth.outcome]):
     * текст ядра — в сводке ошибки причины, а не в сообщении. Тест на
     * сообщении 19.10.2026 проходил, а на телефоне повтор не срабатывал.
     */
    private fun probe(outcome: DnsProbeOutcome, text: String): Diagnostic =
        (XrayHealth.outcome(dns, DnsProbeResult(outcome, 3063, 0, text)) as Outcome.Failure).errors.first()

    /** Журнал 19 октября 2026: CDN без SNI в первой записи отдал сертификат «ни для какого имени». */
    private val certMismatch = probe(
        DnsProbeOutcome.UNREACHABLE,
        "исходящий proxy: proxy/vless/outbound: failed to find an available destination > common/retry: " +
            "[transport/internet/websocket: failed to dial WebSocket > transport/internet/websocket: failed to dial to " +
            "(wss://cdn.example.net/ws) > tls: failed to verify certificate: x509: certificate is not valid for any names, " +
            "but wanted to match cdn.example.net] > common/retry: all retry attempts failed; проба: io: read/write on closed pipe",
    )

    private val refused = probe(
        DnsProbeOutcome.UNREACHABLE,
        "transport/internet/tcp: failed to dial to dest > dial tcp 192.0.2.10:443: connect: connection refused",
    )

    private class Run(val report: ConnectionReport, val checks: List<Boolean>, val log: MemoryLogSink, val book: HealthBook)

    /** [reject] — ответ «сервера» на разбитый ClientHello; без разбиения сервер работает. */
    private fun connect(id: String, reject: Diagnostic, memory: SplitMemory = SplitMemory(), split: Boolean = true): Run = runBlocking {
        val clock = ManualClock(0)
        val sink = MemoryLogSink()
        val book = HealthBook()
        val checks = mutableListOf<Boolean>()
        val health = HealthChecker { s, _ ->
            val splitHello = "\"split_client_hello\":true" in s.compiled.payloadForEngine()
            checks += splitHello
            if (splitHello) Outcome.Failure(listOf(reject)) else Outcome.Success(Unit)
        }
        val plan = ConnectionPlan(listOf(PlannedAttempt(multi.profile(ProfileId(id))!!, listOf("выбран пользователем"))), emptyList(), null, null)
        val log = Logger("t", sink, clock::nowMillis)
        val report = ConnectionOrchestrator(MockBackendCompiler(), MockProxyEngine(), health, book, clock, log, splitMemory = memory) { clock.advance(it) }
            .connect(multi, plan, null, splitClientHello = split)
        Run(report, checks, sink, book)
    }

    private fun Run.events(name: String) = log.snapshot().filter { it.event == name }
    private fun Run.codes() = log.snapshot().mapNotNull { it.fields["code"] }

    @Test
    fun serverThatRejectsTheSplitHelloIsRetriedWithoutItAndRemembered() {
        val memory = SplitMemory()
        val first = connect("xhttp-cdn", certMismatch, memory)
        assertIs<ConnectionReport.Connected>(first.report)
        assertEquals(listOf(true, false), first.checks, "с разбиением — отказ, та же попытка без него — сразу")
        assertEquals(1, first.report.attempts.size, "повтор — та же попытка, а не новый кандидат")
        val record = first.report.attempts.single()
        assertTrue(record.ok)
        assertTrue(record.reasons.any { "не принял разбитый ClientHello" in it }, record.reasons.toString())
        assertTrue(DiagCode.CLIENT_HELLO_SPLIT_REJECTED.name in first.codes(), first.codes().toString())
        assertEquals(HealthState.HEALTHY, first.book.of(ProfileId("xhttp-cdn")).state, "сервер не наказан за отказ разбиению")
        assertEquals(0, first.book.of(ProfileId("xhttp-cdn")).consecutiveFailures)
        assertTrue(memory.rejected(ProfileId("xhttp-cdn")))

        // Переподключение в том же процессе: сразу без разбиения, без лишнего отказа.
        val again = connect("xhttp-cdn", certMismatch, memory)
        assertIs<ConnectionReport.Connected>(again.report)
        assertEquals(listOf(false), again.checks)
        assertEquals(1, again.events("client_hello_split_skipped").size)
        assertTrue(again.report.attempts.single().reasons.any { "этот сервер его не принял" in it })
        assertFalse(DiagCode.CLIENT_HELLO_SPLIT_REJECTED.name in again.codes())
    }

    @Test
    fun refusedServerIsNotRetriedWithoutSplit() {
        val memory = SplitMemory()
        val r = connect("xhttp-cdn", refused, memory)
        assertIs<ConnectionReport.Failed>(r.report)
        assertEquals(listOf(true), r.checks, "отказ TCP — до ClientHello: повтор лишь удвоил бы ожидание")
        assertFalse(memory.rejected(ProfileId("xhttp-cdn")))
        assertEquals(HealthState.FAILED, r.book.of(ProfileId("xhttp-cdn")).state)
    }

    @Test
    fun splitOffMeansNoRetryAndNoMemory() {
        val memory = SplitMemory()
        val r = connect("xhttp-cdn", certMismatch, memory, split = false)
        assertIs<ConnectionReport.Connected>(r.report)
        assertEquals(listOf(false), r.checks)
        assertFalse(memory.rejected(ProfileId("xhttp-cdn")))
    }

    /** Без TLS разбивать нечего (D-68): предупреждение сборки — в журнал, и повтора нет. */
    @Test
    fun serverWithoutTlsLogsSplitNotAppliedAndIsNotRetried() {
        val memory = SplitMemory()
        val r = connect("ss2022", certMismatch, memory)
        assertIs<ConnectionReport.Connected>(r.report)
        assertEquals(listOf(false), r.checks)
        assertTrue(DiagCode.CLIENT_HELLO_SPLIT_NOT_APPLIED.name in r.codes(), r.codes().toString())
        assertFalse(memory.rejected(ProfileId("ss2022")))
    }

    @Test
    fun rejectionIsATlsOrRealityHandshakeErrorAnywhereInTheCauses() {
        fun d(m: String) = Diagnostic.error(DiagCode.ENDPOINT_UNREACHABLE, m)
        assertTrue(SplitFallback.rejectedBy(certMismatch))
        assertTrue(certMismatch.causes.single().message == "проба DNS", "текст ядра — не в сообщении причины")
        assertTrue(SplitFallback.rejectedBy(probe(DnsProbeOutcome.UNREACHABLE, "transport/internet/reality: REALITY: processed invalid connection")))
        assertTrue(SplitFallback.rejectedBy(d("dial: remote error: tls: handshake failure")))
        assertTrue(SplitFallback.rejectedBy(d("transport/internet/reality: REALITY: processed invalid connection")))
        assertTrue(SplitFallback.rejectedBy(d("сервер недоступен").withCause(d("x509: certificate signed by unknown authority"))))

        assertFalse(SplitFallback.rejectedBy(refused))
        assertFalse(SplitFallback.rejectedBy(probe(DnsProbeOutcome.UNREACHABLE, "context deadline exceeded")))
        // TLS с DNS-сервером уже через сервер профиля: соединение с сервером было.
        assertFalse(SplitFallback.rejectedBy(probe(DnsProbeOutcome.TLS, "tls: failed to verify certificate: x509: certificate has expired")))
        assertFalse(SplitFallback.rejectedBy(d("dial tcp 192.0.2.10:443: i/o timeout")))
        assertFalse(SplitFallback.rejectedBy(d("read tcp 10.0.0.2:40000->192.0.2.10:443: read: connection reset by peer")))
        // Путь пакета Xray — не ошибка рукопожатия.
        assertFalse(SplitFallback.rejectedBy(d("transport/internet/tls: Failed to query ECH DNS record for domain")))
        assertFalse(SplitFallback.rejectedBy(d("проба TLS: не ответил")))
    }
}
