package com.dpsmpx.dppass.engine.xray

import com.dpsmpx.dppass.config.ConfigLoader
import com.dpsmpx.dppass.diagnostics.DiagCode
import com.dpsmpx.dppass.diagnostics.Diagnostic
import com.dpsmpx.dppass.diagnostics.Outcome
import com.dpsmpx.dppass.diagnostics.Severity
import com.dpsmpx.dppass.engine.CompilePlan
import com.dpsmpx.dppass.engine.CompiledConfig
import com.dpsmpx.dppass.engine.EngineSession
import com.dpsmpx.dppass.engine.EngineState
import com.dpsmpx.dppass.engine.SocketProtector
import com.dpsmpx.dppass.engine.TrafficStats
import com.dpsmpx.dppass.engine.TunInput
import com.dpsmpx.dppass.engine.mock.MockBackendCompiler
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNull
import kotlin.test.assertSame
import kotlin.test.assertTrue
import kotlinx.coroutines.runBlocking

/** Мост без библиотеки: отвечает как настоящий (одно ядро, неполная проверка при работе). */
private class FakeRuntime : XrayRuntime {
    var running = false
    var validateAnswer: XrayResult = XrayResult.Ok
    var startAnswer: XrayResult = XrayResult.Ok
    var stopAnswer: XrayResult = XrayResult.Ok
    var traffic = TrafficStats(0, 0)
    val starts = mutableListOf<Triple<Int, Int, SocketProtector?>>()
    var stops = 0

    override fun version(): String = XrayBackend.VERSION

    override fun validate(config: ByteArray): XrayResult = if (running) XrayResult.Partial else validateAnswer

    override fun start(config: ByteArray, tunFd: Int, tunMtu: Int, protector: SocketProtector?): XrayResult {
        if (running) return XrayResult.Failed(XrayFailureKind.RUNNING, "ядро уже запущено")
        starts += Triple(tunFd, tunMtu, protector)
        if (startAnswer == XrayResult.Ok) running = true
        return startAnswer
    }

    override fun stop(): XrayResult {
        stops++
        running = false
        return stopAnswer
    }

    override fun traffic(): TrafficStats? = traffic.takeIf { running }

    val probes = mutableListOf<String>()
    var probeAnswer = DnsProbeResult(DnsProbeOutcome.OK, 40, 512, "")

    override fun probeDns(target: String, timeoutMillis: Int): DnsProbeResult {
        probes += target
        return if (running) probeAnswer else DnsProbeResult(DnsProbeOutcome.NOT_RUNNING, 0, 0, "ядро не запущено")
    }
}

private const val UUID = "00000000-0000-4000-8000-000000000001"

class XrayProxyEngineTest {
    private val ir = ConfigLoader().load(File(System.getProperty("dppass.repoRoot"), "tests/data/configs/valid-minimal.json").readText())
        .valueOrNull()!!.ir
    private val compiled: CompiledConfig = XrayCompiler().compile(ir, CompilePlan(ir.profiles[0].id, withTun = true)).valueOrNull()!!

    @Test
    fun validateAcceptsAndRefusesForeignConfig() = runBlocking {
        val rt = FakeRuntime()
        val engine = XrayProxyEngine(Outcome.Success(rt))
        val ok = engine.validate(compiled)
        assertIs<Outcome.Success<Unit>>(ok)
        assertTrue(ok.diagnostics.isEmpty())

        val mock = MockBackendCompiler().compile(ir, CompilePlan(ir.profiles[0].id, withTun = true)).valueOrNull()!!
        assertEquals(DiagCode.BACKEND_REJECTED_CONFIG, engine.validate(mock).errors.single().code)
        assertEquals(DiagCode.BACKEND_REJECTED_CONFIG, engine.start(mock, null).errors.single().code)
        assertTrue(rt.starts.isEmpty(), "чужая конфигурация не доходит до ядра")
    }

    @Test
    fun coreTextIsACauseAndIsRedacted() = runBlocking {
        val rt = FakeRuntime().apply {
            validateAnswer = XrayResult.Failed(XrayFailureKind.CONFIG, "infra/conf: invalid user id $UUID at vless://$UUID@203.0.113.10:443/x")
        }
        val d = XrayProxyEngine(Outcome.Success(rt)).validate(compiled).errors.single()
        assertEquals(DiagCode.BACKEND_REJECTED_CONFIG, d.code)
        val cause = d.causes.single()
        val text = cause.error?.message!!
        assertTrue("infra/conf: invalid user id" in text, text)
        assertFalse(UUID in text, "текст ядра — только после Redactor (D-11): $text")
        assertFalse(UUID in d.message + cause.message)
    }

    @Test
    fun coreTextIsBounded() = runBlocking {
        val rt = FakeRuntime().apply { validateAnswer = XrayResult.Failed(XrayFailureKind.CONFIG, "x".repeat(100_000)) }
        val text = XrayProxyEngine(Outcome.Success(rt)).validate(compiled).errors.single().causes.single().error?.message!!
        assertTrue(text.length <= CORE_TEXT_LIMIT, "длина ${text.length}")
    }

    @Test
    fun startPassesTunAndProtectorAndRunsOneSession() = runBlocking {
        val rt = FakeRuntime()
        val engine = XrayProxyEngine(Outcome.Success(rt))
        val protector = SocketProtector { true }
        val s = engine.start(compiled, TunInput(42, XrayBackend.TUN_MTU, protector)).valueOrNull()!!
        assertEquals(EngineState.RUNNING, s.state())
        val (fd, mtu, p) = rt.starts.single()
        assertEquals(42, fd)
        assertEquals(XrayBackend.TUN_MTU, mtu)
        assertSame(protector, p)

        val again = engine.start(compiled, null)
        assertEquals(DiagCode.BACKEND_ALREADY_RUNNING, again.errors.single().code)
        assertEquals(1, rt.starts.size, "второй запуск не доходит до ядра")

        // Проверка при работающем ядре — неполная, и это видно находкой, а не молчанием.
        val v = engine.validate(compiled)
        assertIs<Outcome.Success<Unit>>(v)
        val note = v.diagnostics.single()
        assertEquals(DiagCode.BACKEND_VALIDATION_PARTIAL, note.code)
        assertEquals(Severity.INFO, note.severity)
    }

    @Test
    fun withoutTunNothingIsPassed() = runBlocking {
        val rt = FakeRuntime()
        XrayProxyEngine(Outcome.Success(rt)).start(compiled, null).valueOrNull()!!
        assertEquals(Triple(-1, 0, null), rt.starts.single())
    }

    @Test
    fun statsAndStopLifecycle() = runBlocking {
        val rt = FakeRuntime()
        val engine = XrayProxyEngine(Outcome.Success(rt))
        val first = engine.start(compiled, null).valueOrNull()!!
        rt.traffic = TrafficStats(100, 2000)
        assertEquals(TrafficStats(100, 2000), first.stats())
        rt.traffic = TrafficStats(150, 2500)
        first.stop()
        assertEquals(EngineState.STOPPED, first.state())
        assertEquals(TrafficStats(150, 2500), first.stats(), "после остановки — последние счётчики")
        first.stop()
        assertEquals(1, rt.stops, "повторная остановка не трогает ядро")

        val second = engine.start(compiled, null).valueOrNull()!!
        first.stop()
        assertEquals(1, rt.stops, "старая сессия не останавливает новую")
        assertEquals(EngineState.RUNNING, second.state())
        rt.stopAnswer = XrayResult.Failed(XrayFailureKind.START, "close failed")
        second.stop()
        assertEquals(EngineState.FAILED, second.state())
        assertTrue(engine.start(compiled, null) is Outcome.Success, "после неудачной остановки ядро можно запустить снова")
    }

    @Test
    fun failureKindsMapToCodes() = runBlocking {
        val cases = mapOf(
            XrayFailureKind.CONFIG to DiagCode.BACKEND_REJECTED_CONFIG,
            XrayFailureKind.START to DiagCode.BACKEND_START_FAILED,
            XrayFailureKind.CONTRACT to DiagCode.BACKEND_START_FAILED,
            XrayFailureKind.RUNNING to DiagCode.BACKEND_ALREADY_RUNNING,
        )
        for ((kind, code) in cases) {
            val rt = FakeRuntime().apply { startAnswer = XrayResult.Failed(kind, "boom") }
            val engine = XrayProxyEngine(Outcome.Success(rt))
            val d = engine.start(compiled, null).errors.single()
            assertEquals(code, d.code, "$kind")
            assertEquals(code, d.causes.single().code, "$kind")
            assertFalse(rt.running)
            rt.startAnswer = XrayResult.Ok
            assertTrue(engine.start(compiled, null) is Outcome.Success, "$kind: неудачный запуск не занимает ядро")
        }
    }

    @Test
    fun unavailableRuntimeAnswersEveryCall() = runBlocking {
        val reason = Diagnostic.error(DiagCode.BACKEND_NOT_AVAILABLE, "библиотека ядра не загружена")
        val engine = XrayProxyEngine(Outcome.failure(reason))
        for (r in listOf(engine.validate(compiled), engine.start(compiled, null))) {
            val d = r.errors.single()
            assertEquals(DiagCode.BACKEND_NOT_AVAILABLE, d.code)
            assertEquals(listOf(reason), d.causes)
        }
    }

    @Test
    fun missingLibraryIsNotAvailable() {
        val thrown = JniXrayRuntime.load({ throw UnsatisfiedLinkError("no dppassxray in java.library.path") }, "/nonexistent")
        assertEquals(DiagCode.BACKEND_NOT_AVAILABLE, thrown.errors.single().code)
        // Загрузчик «ничего не сделал» — первый вызов JNI тоже не находит библиотеку.
        val silent = JniXrayRuntime.load({}, "/nonexistent")
        assertEquals(DiagCode.BACKEND_NOT_AVAILABLE, silent.errors.single().code)
    }

    @Test
    fun bridgeAnswerDecoding() {
        // Договор с tools/xray/jni: статус в первом байте, затем текст UTF-8.
        assertEquals(XrayResult.Ok, XrayJni.decode(byteArrayOf(0)))
        assertEquals(XrayResult.Partial, XrayJni.decode(byteArrayOf(5)))
        val failed = assertIs<XrayResult.Failed>(XrayJni.decode(byteArrayOf(1) + "сбой 🌐".encodeToByteArray()))
        assertEquals(XrayFailureKind.CONFIG, failed.kind)
        assertEquals("сбой 🌐", failed.text)
        assertEquals(XrayFailureKind.CONTRACT, assertIs<XrayResult.Failed>(XrayJni.decode(byteArrayOf(77))).kind)
        assertEquals(XrayFailureKind.CONTRACT, assertIs<XrayResult.Failed>(XrayJni.decode(byteArrayOf())).kind)
        assertEquals(listOf(1, 2, 3, 4), XrayFailureKind.entries.map { it.code }, "коды — договор с bridge.Kind")
        assertNull(XrayFailureKind.of(0))
        assertFalse("сбой" in failed.toString(), "toString не печатает текст ядра")
    }

    @Test
    fun healthProbeGoesToTunnelDnsServerAndMapsOutcomes() = runBlocking {
        // D-32: проба — к DNS-серверу конфигурации через туннель; исход — код здоровья.
        val rt = FakeRuntime()
        val engine = XrayProxyEngine(Outcome.Success(rt))
        assertIs<Outcome.Success<EngineSession>>(engine.start(compiled, null))
        assertIs<Outcome.Success<Unit>>(engine.probeHealth(ir.dns, 1000))
        assertEquals(listOf("https://dns.example.net/dns-query"), rt.probes)

        val cases = mapOf(
            DnsProbeOutcome.UNREACHABLE to DiagCode.ENDPOINT_UNREACHABLE,
            DnsProbeOutcome.TLS to DiagCode.TLS_HANDSHAKE_FAILED,
            DnsProbeOutcome.STALLED to DiagCode.PAYLOAD_STALLED,
            DnsProbeOutcome.BAD_ANSWER to DiagCode.HEALTH_CHECK_FAILED,
        )
        for ((outcome, code) in cases) {
            rt.probeAnswer = DnsProbeResult(outcome, 900, 10, "Post \"https://dns.example.net/abc123secret456\": EOF")
            val r = assertIs<Outcome.Failure>(engine.probeHealth(ir.dns, 1000), "$outcome")
            assertEquals(code, r.errors.single().code)
            val text = r.errors.single().renderWithCauses()
            assertFalse("abc123secret456" in text, "личный путь DoH попал в диагностику: $text")
        }
    }
}
