package com.dpsmpx.dppass.tests.xrayjni

import com.dpsmpx.dppass.config.ConfigIr
import com.dpsmpx.dppass.config.ConfigLoader
import com.dpsmpx.dppass.config.ProtocolSpec
import com.dpsmpx.dppass.config.SecuritySpec
import com.dpsmpx.dppass.config.TransportSpec
import com.dpsmpx.dppass.core.Endpoint
import com.dpsmpx.dppass.core.Host
import com.dpsmpx.dppass.core.IpAddress
import com.dpsmpx.dppass.diagnostics.DiagCode
import com.dpsmpx.dppass.diagnostics.Outcome
import com.dpsmpx.dppass.diagnostics.Secret
import com.dpsmpx.dppass.engine.CompilePlan
import com.dpsmpx.dppass.engine.CompiledConfig
import com.dpsmpx.dppass.engine.ConnNetwork
import com.dpsmpx.dppass.engine.ConnState
import com.dpsmpx.dppass.engine.EngineState
import com.dpsmpx.dppass.engine.ShareSpec
import com.dpsmpx.dppass.engine.SocketProtector
import com.dpsmpx.dppass.engine.xray.DnsProbeOutcome
import com.dpsmpx.dppass.engine.xray.GeoKind
import com.dpsmpx.dppass.engine.xray.GeoMatchResult
import com.dpsmpx.dppass.engine.xray.JniXrayRuntime
import com.dpsmpx.dppass.engine.xray.XrayBackend
import com.dpsmpx.dppass.engine.xray.XrayCompiler
import com.dpsmpx.dppass.engine.xray.XrayFailureKind
import com.dpsmpx.dppass.engine.xray.XrayProxyEngine
import com.dpsmpx.dppass.engine.xray.XrayResult
import com.dpsmpx.dppass.engine.xray.XrayRuntime
import com.dpsmpx.dppass.routing.RouteQuery
import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.TestInstance
import java.io.File
import java.io.IOException
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.net.SocketTimeoutException
import java.nio.file.Files
import java.util.concurrent.ConcurrentLinkedQueue
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.TimeUnit
import kotlin.concurrent.thread
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.test.fail

/**
 * Мост Xray через JNI в JVM хоста (D-25): тот же `tools/xray`, что идёт в
 * APK, собранный для хоста (`tools/xray/native.py host`, с тестовым
 * входом `dppass_testinbound`). Проверяется договор, который на
 * устройстве увидеть уже поздно: версия ядра, проверка и её неполнота
 * при работе, запуск и остановка, один экземпляр, вызов защитника из
 * потоков Go и закрытие пути при его отказе (в том числе исключением),
 * счётчики, отказ конфигурации с геоданными без каталога, сопоставление с
 * геоданными для объяснения решений (D-27).
 *
 * Соединения идут через тестовый вход на loopback (`dokodemo-door`):
 * TUN на хосте не поднять, а путь «ядро → защитник → сервер» тот же.
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class XrayJniTest {
    private lateinit var runtime: XrayRuntime
    private lateinit var lib: String
    private lateinit var assets: File

    @BeforeAll
    fun load() {
        lib = System.getProperty("dppass.xray.lib").orEmpty()
        if (lib.isEmpty() || !File(lib).isFile) fail("нет библиотеки ядра: -Pdppass.xray.lib (tools/xray/native.py host)")
        assets = Files.createTempDirectory("dppass-xray-assets").toFile().also { it.deleteOnExit() }
        runtime = loadWith(assets)
    }

    /** Загрузка библиотеки (повторная — ничего не делает) и каталог геоданных моста. */
    private fun loadWith(dir: File): XrayRuntime = when (val r = JniXrayRuntime.load({ System.load(lib) }, dir.path)) {
        is Outcome.Failure -> fail("библиотека не загрузилась: ${r.diagnostics.map { it.render() }}")
        is Outcome.Success -> r.value
    }

    @AfterEach
    fun stop() {
        assertEquals(XrayResult.Ok, runtime.stop(), "остановка после теста")
    }

    // ---- версия и проверка ----

    @Test
    fun versionIsPinnedCore() {
        assertEquals(XrayBackend.VERSION, runtime.version())
    }

    @Test
    fun compiledConfigPassesFullValidation() {
        assertEquals(XrayResult.Ok, runtime.validate(compiled("valid-minimal.json", withTun = true).bytes()))
    }

    @Test
    fun brokenConfigIsConfigFailure() {
        val r = assertIs<XrayResult.Failed>(runtime.validate("""{"outbounds": [""".encodeToByteArray()))
        assertEquals(XrayFailureKind.CONFIG, r.kind)
    }

    /** Каталог геоданных пуст (на устройстве — перенос набора не удался, D-27): ядро отвергает geoip/geosite. */
    @Test
    fun geodataWithoutAssetsIsRejected() {
        val multi = compiled("valid-multi.json", withTun = true)
        assertTrue("geoip:" in multi.payloadForEngine(), "в корпусе valid-multi должно быть правило geoip")
        val r = assertIs<XrayResult.Failed>(runtime.validate(multi.bytes()))
        assertEquals(XrayFailureKind.CONFIG, r.kind)
    }

    @Test
    fun foreignInboundIsRejectedByBridgePolicy() {
        val socks = """{"tag": "s", "protocol": "socks", "listen": "127.0.0.1", "port": ${freePort()}}"""
        val r = assertIs<XrayResult.Failed>(runtime.validate(config(socks)))
        assertEquals(XrayFailureKind.CONFIG, r.kind)
        assertTrue("T11" in r.text, "отказ политики моста: ${r.text}")
    }

    /** D-51: входы раздачи компилятора (SOCKS с паролем на адресах раздачи) мост пропускает. */
    @Test
    fun shareInboundPassesBridgePolicy() {
        val ir = ir("valid-minimal.json")
        val share = ShareSpec(
            listOf(ShareSpec.Endpoint(IpAddress.parse("192.168.43.1")!!, 24), ShareSpec.Endpoint(IpAddress.parse("10.42.0.1")!!, 24)),
            41234,
            Secret("u-test"),
            Secret("p-test-0123456789"),
        )
        val compiled = XrayCompiler().compile(ir, CompilePlan(ir.profiles.first().id, true, share)).valueOrNull() ?: fail("раздача не скомпилирована")
        val r = runtime.validate(compiled.bytes())
        assertEquals(XrayResult.Ok, r, (r as? XrayResult.Failed)?.text)
    }

    /** D-55: исходящий к устройству раздачи (socks с паролем на частный IPv4) ядро принимает целиком. */
    @Test
    fun relayDeviceOutboundPassesFullValidation() {
        val base = ir("valid-minimal.json")
        val relay = base.profiles.first().copy(
            endpoint = Endpoint(Host.Ip(IpAddress.parse("192.168.43.1")!!), 41234),
            protocol = ProtocolSpec.Socks(Secret("u-test"), Secret("p-test-0123456789")),
            transport = TransportSpec.Tcp,
            security = SecuritySpec.None,
        )
        val ir = base.copy(profiles = listOf(relay))
        val compiled = XrayCompiler().compile(ir, CompilePlan(relay.id, true)).valueOrNull() ?: fail("устройство раздачи не скомпилировано")
        val r = runtime.validate(compiled.bytes())
        assertEquals(XrayResult.Ok, r, (r as? XrayResult.Failed)?.text)
    }

    // ---- запуск, один экземпляр, договор ----

    @Test
    fun oneCoreAtATimeAndPartialValidationWhileRunning() {
        assertEquals(XrayResult.Ok, runtime.start(config(), NO_TUN, 0, null))
        val again = assertIs<XrayResult.Failed>(runtime.start(config(), NO_TUN, 0, null))
        assertEquals(XrayFailureKind.RUNNING, again.kind)
        assertEquals(XrayResult.Partial, runtime.validate(config()))
        assertNotNull(runtime.traffic())
        assertEquals(XrayResult.Ok, runtime.stop())
        assertNull(runtime.traffic(), "после остановки счётчиков нет")
        assertEquals(XrayResult.Ok, runtime.stop(), "повторная остановка — не ошибка")
    }

    @Test
    fun tunWithoutProtectorIsContractFailure() {
        val tun = compiled("valid-minimal.json", withTun = true).bytes()
        // fd не используется: мост отказывает до того, как ядро его тронет.
        val r = assertIs<XrayResult.Failed>(runtime.start(tun, 1_000_000, 1500, null))
        assertEquals(XrayFailureKind.CONTRACT, r.kind)
        val noFd = assertIs<XrayResult.Failed>(runtime.start(tun, NO_TUN, 1500, SocketProtector { true }))
        assertEquals(XrayFailureKind.CONTRACT, noFd.kind)
    }

    // ---- защитник сокетов из потоков Go ----

    @Test
    fun protectorSeesCoreSocketAndDataFlows() {
        val echo = EchoServer()
        val seen = ConcurrentLinkedQueue<Int>()
        val protector = SocketProtector { fd -> seen += fd; true }
        val inbound = freePort()
        assertEquals(XrayResult.Ok, runtime.start(config(testInbound(inbound, echo.port)), NO_TUN, 0, protector))
        val message = "dppass-jni-".repeat(64).encodeToByteArray()
        dialCore(inbound).use { s ->
            s.getOutputStream().write(message)
            val back = s.getInputStream().readNBytes(message.size)
            assertTrue(back.contentEquals(message), "эхо через ядро вернуло другие байты")
        }
        assertTrue(echo.accepted.poll(5, TimeUnit.SECONDS) != null, "сервер не получил соединение ядра")
        assertTrue(seen.isNotEmpty() && seen.all { it >= 0 }, "защитник не получил сокет ядра: $seen")
        // Счётчики proxy на хосте пополняются после закрытия (freedom сращивает сокеты ОС).
        val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5)
        while (true) {
            val t = assertNotNull(runtime.traffic())
            if (t.uplinkBytes >= message.size && t.downlinkBytes >= message.size) break
            if (System.nanoTime() > deadline) fail("счётчики proxy: $t, ожидалось ≥ ${message.size}")
            Thread.sleep(20)
        }
        echo.close()
    }

    // ---- учёт соединений (D-106) ----

    @Test
    fun connectionTrackingSeesCoreConnectionAndForgetsWhenOff() {
        val echo = EchoServer()
        val inbound = freePort()
        runtime.setConnectionTracking(true)
        try {
            assertEquals(XrayResult.Ok, runtime.start(config(testInbound(inbound, echo.port)), NO_TUN, 0, SocketProtector { true }))
            val message = "dppass-conn-".repeat(32).encodeToByteArray()
            dialCore(inbound).use { s ->
                s.getOutputStream().write(message)
                s.getInputStream().readNBytes(message.size)
            }
            val target = "127.0.0.1:${echo.port}"
            val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5)
            while (true) {
                val snap = runtime.connections()
                assertTrue(snap.enabled)
                assertEquals(0, snap.malformed, "строки снимка — по договору моста")
                val c = snap.connections.firstOrNull { it.target == target }
                if (c != null && c.state != ConnState.OPEN) {
                    assertEquals(ConnNetwork.TCP, c.network)
                    assertEquals("test-in", c.inbound)
                    assertEquals("proxy", c.route)
                    assertEquals(message.size.toLong(), c.upBytes, "к серверу — ровно отправленное")
                    assertTrue(c.upChunks >= 1)
                    break
                }
                if (System.nanoTime() > deadline) fail("соединение к $target не закрылось в учёте: ${snap.connections}")
                Thread.sleep(20)
            }
        } finally {
            runtime.setConnectionTracking(false)
            echo.close()
        }
        val off = runtime.connections()
        assertFalse(off.enabled)
        assertTrue(off.connections.isEmpty(), "выключение стирает учтённое")
    }

    @Test
    fun refusedProtectionClosesThePath() = assertPathClosed(SocketProtector { false })

    @Test
    fun throwingProtectorIsRefusalNotCrash() = assertPathClosed(SocketProtector { error("защитник упал") })

    private fun assertPathClosed(protector: SocketProtector) {
        val echo = EchoServer()
        val calls = ConcurrentLinkedQueue<Int>()
        val counting = SocketProtector { fd -> calls += fd; protector.protect(fd) }
        val inbound = freePort()
        assertEquals(XrayResult.Ok, runtime.start(config(testInbound(inbound, echo.port)), NO_TUN, 0, counting))
        dialCore(inbound).use { s ->
            s.getOutputStream().write("must not arrive".encodeToByteArray())
            val n = try {
                s.getInputStream().read(ByteArray(16))
            } catch (e: SocketTimeoutException) {
                fail("ядро не закрыло соединение, а повисло")
            } catch (e: IOException) {
                -1
            }
            assertEquals(-1, n, "соединение без защиты передало данные")
        }
        assertTrue(calls.isNotEmpty(), "защитник не был спрошен")
        assertNull(echo.accepted.poll(300, TimeUnit.MILLISECONDS), "незащищённый сокет ядра соединился с сервером")
        echo.close()
    }

    // ---- проба здоровья (D-32) ----

    @Test
    fun dnsProbeGoesThroughProxyAndProtector() {
        assertEquals(DnsProbeOutcome.NOT_RUNNING, runtime.probeDns("udp://127.0.0.1:53", 1000).outcome)
        val dns = DatagramSocket(0, LOOPBACK)
        val server = thread(isDaemon = true) {
            val buf = ByteArray(512)
            val p = DatagramPacket(buf, buf.size)
            dns.receive(p)
            buf[2] = (buf[2].toInt() or 0x80).toByte() // ответ: флаг QR, тот же id и вопрос
            dns.send(DatagramPacket(buf, p.length, p.socketAddress))
        }
        val seen = ConcurrentLinkedQueue<Int>()
        assertEquals(XrayResult.Ok, runtime.start(config(), NO_TUN, 0, SocketProtector { fd -> seen += fd; true }))
        val r = runtime.probeDns("udp://127.0.0.1:${dns.localPort}", 3000)
        assertEquals(DnsProbeOutcome.OK, r.outcome, "проба: $r ${r.text}")
        assertTrue(r.receivedBytes > 0, "ответ пришёл через ядро: $r")
        assertTrue(seen.isNotEmpty(), "сокет пробы прошёл мимо защитника")
        server.join(1000)
        dns.close()
        assertEquals(DnsProbeOutcome.CONTRACT, runtime.probeDns("dns://127.0.0.1", 1000).outcome)
    }

    // ---- замер через туннель (D-61) ----

    /**
     * Договор JNI замера: исход, пинги, байты и текст доходят до Kotlin. Через
     * ядро до локального сервера без доверенного сертификата — отказ TLS после
     * соединения через защитника (сертификат проверяется всегда, T5).
     */
    @Test
    fun speedTestGoesThroughProxyAndKeepsTheContract() {
        assertEquals(DnsProbeOutcome.NOT_RUNNING, runtime.speedTest("https://127.0.0.1/__down", 2, 1024, 1000, 3000).outcome)
        val server = ServerSocket(0, 4, LOOPBACK)
        val accept = thread(isDaemon = true) {
            runCatching { server.accept().use { it.getOutputStream().write("not tls\r\n".toByteArray()) } }
        }
        val seen = ConcurrentLinkedQueue<Int>()
        assertEquals(XrayResult.Ok, runtime.start(config(), NO_TUN, 0, SocketProtector { fd -> seen += fd; true }))
        val r = runtime.speedTest("https://127.0.0.1:${server.localPort}/__down", 2, 1024, 1000, 3000)
        assertEquals(DnsProbeOutcome.TLS, r.outcome, "замер: $r ${r.text}")
        assertTrue(r.pingMicros.isEmpty(), "до пингов дело не дошло: $r")
        assertTrue(seen.isNotEmpty(), "сокет замера прошёл мимо защитника")
        accept.join(1000)
        server.close()
        assertEquals(DnsProbeOutcome.CONTRACT, runtime.speedTest("http://127.0.0.1/__down", 2, 1024, 1000, 3000).outcome)
    }

    // ---- геоданные для объяснения решений (D-27) ----

    /**
     * Каталог геоданных пуст (перенос набора не удался, D-27): код не
     * сопоставляется — отказ «набора нет», а не «не попадает» и не «такого
     * кода нет».
     */
    @Test
    fun geoMatchWithoutSetIsRefused() {
        val r = assertIs<XrayResult.Failed>(runtime.geoMatch(GeoKind.SITE, "zz", "example.org".encodeToByteArray()))
        assertEquals(XrayFailureKind.CONTRACT, r.kind)
        val bad = assertIs<XrayResult.Failed>(runtime.geoMatch(GeoKind.IP, "zz", byteArrayOf(1, 2, 3)))
        assertEquals(XrayFailureKind.CONTRACT, bad.kind)
        val engine = XrayProxyEngine(Outcome.Success(runtime))
        val policy = ir("valid-multi.json").routing
        assertTrue(policy.rules.any { it.conditions.geoIps.isNotEmpty() }, "в корпусе valid-multi должно быть правило geoip")
        val explained = engine.explain(policy, RouteQuery(ip = IpAddress.parse("198.51.100.1")))
        assertEquals(DiagCode.GEODATA_UNAVAILABLE, explained.errors.single().code)
    }

    /** Синтетический набор: geosite DPPASS-JNI — домен example.org, geoip DPPASS-JNI — 192.0.2.0/24 и 2001:db8::/32. */
    @Test
    fun geoMatchAnswersFromTheSet() {
        val dir = Files.createTempDirectory("dppass-xray-geo").toFile().also { it.deleteOnExit() }
        writeGeoSet(dir)
        val rt = loadWith(dir)
        try {
            fun site(name: String) = rt.geoMatch(GeoKind.SITE, "dppass-jni", name.encodeToByteArray())
            fun ip(text: String) = rt.geoMatch(GeoKind.IP, "dppass-jni", IpAddress.parse(text)!!.toBytes())
            assertEquals(GeoMatchResult.Answer(true), site("www.Example.org"))
            assertEquals(GeoMatchResult.Answer(false), site("example.org.test"))
            assertEquals(GeoMatchResult.Answer(true), ip("192.0.2.200"))
            assertEquals(GeoMatchResult.Answer(true), ip("2001:db8::1"))
            assertEquals(GeoMatchResult.Answer(false), ip("198.51.100.1"))
            // Набор есть, а кода в нём нет — «такого кода нет», как у проверки конфигурации.
            val unknown = assertIs<XrayResult.Failed>(rt.geoMatch(GeoKind.SITE, "zz", "example.org".encodeToByteArray()))
            assertEquals(XrayFailureKind.CONFIG, unknown.kind)
        } finally {
            loadWith(assets)
        }
    }

    /** geosite.dat и geoip.dat в формате Xray (common/geodata/geodat.proto) — байтами, без библиотеки protobuf. */
    private fun writeGeoSet(dir: File) {
        fun field(number: Int, body: ByteArray): ByteArray {
            require(body.size < 128) { "длина — один байт varint" }
            return byteArrayOf(((number shl 3) or 2).toByte(), body.size.toByte()) + body
        }
        fun varint(number: Int, value: Int): ByteArray = byteArrayOf((number shl 3).toByte(), value.toByte())
        val code = field(1, "DPPASS-JNI".encodeToByteArray())
        val domain = varint(1, 2) + field(2, "example.org".encodeToByteArray()) // Domain.Type.Domain
        File(dir, "geosite.dat").writeBytes(field(1, code + field(2, domain)))
        val v4 = field(1, IpAddress.parse("192.0.2.0")!!.toBytes()) + varint(2, 24)
        val v6 = field(1, IpAddress.parse("2001:db8::")!!.toBytes()) + varint(2, 32)
        File(dir, "geoip.dat").writeBytes(field(1, code + field(2, v4) + field(2, v6)))
    }

    // ---- ProxyEngine поверх JNI ----

    @Test
    fun proxyEngineRunsCompiledConfigThroughJni() = runBlocking {
        val engine = XrayProxyEngine(Outcome.Success(runtime))
        val config = compiled("valid-minimal.json", withTun = false)
        assertIs<Outcome.Success<Unit>>(engine.validate(config))
        val session = when (val s = engine.start(config, null)) {
            is Outcome.Failure -> fail("ядро не запустилось: ${s.diagnostics.map { it.render() }}")
            is Outcome.Success -> s.value
        }
        assertEquals(EngineState.RUNNING, session.state())
        val second = assertIs<Outcome.Failure>(engine.start(config, null))
        assertEquals(DiagCode.BACKEND_ALREADY_RUNNING, second.errors.single().code)
        session.stop()
        assertEquals(EngineState.STOPPED, session.state())
    }

    // ---- помощники ----

    private fun ir(name: String): ConfigIr {
        val text = File(System.getProperty("dppass.repoRoot"), "tests/data/configs/$name").readText()
        return ConfigLoader().load(text).valueOrNull()?.ir ?: fail("$name не разобран")
    }

    private fun compiled(name: String, withTun: Boolean): CompiledConfig {
        val ir = ir(name)
        val plan = CompilePlan(ir.profiles.first().id, withTun)
        return when (val r = XrayCompiler().compile(ir, plan)) {
            is Outcome.Failure -> fail("$name не скомпилирован: ${r.diagnostics.map { it.render() }}")
            is Outcome.Success -> r.value
        }
    }

    private fun CompiledConfig.bytes(): ByteArray = payloadForEngine().encodeToByteArray()

    /** Конфигурация в духе компилятора DPpass: счётчики proxy, исходящий proxy — freedom. */
    private fun config(inbounds: String = ""): ByteArray = """
        {"log": {"loglevel": "none"},
         "stats": {},
         "policy": {"system": {"statsOutboundUplink": true, "statsOutboundDownlink": true}},
         "inbounds": [$inbounds],
         "outbounds": [{"tag": "proxy", "protocol": "freedom"}, {"tag": "block", "protocol": "blackhole"}]}
    """.trimIndent().encodeToByteArray()

    private fun testInbound(port: Int, target: Int): String =
        """{"tag": "test-in", "protocol": "dokodemo-door", "listen": "127.0.0.1", "port": $port,
            "settings": {"address": "127.0.0.1", "port": $target, "network": "tcp"}}"""

    private fun freePort(): Int = ServerSocket(0, 1, LOOPBACK).use { it.localPort }

    /** Вход ядра открывается не мгновенно после запуска — несколько попыток. */
    private fun dialCore(port: Int): Socket {
        val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5)
        while (true) {
            try {
                return Socket().apply {
                    connect(InetSocketAddress(LOOPBACK, port), 1000)
                    soTimeout = 5000
                }
            } catch (e: IOException) {
                if (System.nanoTime() > deadline) fail("тестовый вход ядра не принимает соединения: ${e.message}")
                Thread.sleep(20)
            }
        }
    }

    private class EchoServer : AutoCloseable {
        private val server = ServerSocket(0, 16, LOOPBACK)
        val port: Int = server.localPort
        val accepted = LinkedBlockingQueue<Unit>()

        init {
            thread(isDaemon = true, name = "echo") {
                while (true) {
                    val c = try {
                        server.accept()
                    } catch (e: IOException) {
                        return@thread
                    }
                    accepted += Unit
                    thread(isDaemon = true) { c.use { it.getInputStream().transferTo(it.getOutputStream()) } }
                }
            }
        }

        override fun close() = server.close()
    }

    private companion object {
        const val NO_TUN = -1
        val LOOPBACK: java.net.InetAddress = java.net.InetAddress.getLoopbackAddress()
    }
}
