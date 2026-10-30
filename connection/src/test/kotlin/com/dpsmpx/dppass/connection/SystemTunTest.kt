package com.dpsmpx.dppass.connection

import com.dpsmpx.dppass.core.Cidr
import com.dpsmpx.dppass.core.IpAddress
import com.dpsmpx.dppass.core.ManualClock
import com.dpsmpx.dppass.diagnostics.Logger
import com.dpsmpx.dppass.diagnostics.MemoryLogSink
import com.dpsmpx.dppass.diagnostics.Outcome
import com.dpsmpx.dppass.engine.CompiledConfig
import com.dpsmpx.dppass.engine.EngineSession
import com.dpsmpx.dppass.engine.EngineState
import com.dpsmpx.dppass.engine.HostAddress
import com.dpsmpx.dppass.engine.ProxyEngine
import com.dpsmpx.dppass.engine.SystemTun
import com.dpsmpx.dppass.engine.TrafficStats
import com.dpsmpx.dppass.engine.TunInput
import com.dpsmpx.dppass.engine.xray.XrayBackend
import com.dpsmpx.dppass.engine.xray.XrayCompiler
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertIs
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** TUN, который создаёт само ядро (Windows, D-97): через оркестратор — без fd, а настройки адаптера — в конфигурации. */
class SystemTunTest {
    private val clock = ManualClock(1_000)
    private val system = SystemTun(
        addresses = listOf(HostAddress(IpAddress.parse("172.19.0.1")!!, 30)),
        routes = listOf(Cidr.ALL_V4, Cidr.ALL_V6),
        dns = listOf(IpAddress.parse(XrayBackend.TUN_DNS4)!!),
    )

    /** Ядро, которое запоминает, с чем его запустили. */
    private class Recording : ProxyEngine {
        override val capabilities = XrayBackend.CAPABILITIES
        val payloads = mutableListOf<String>()
        val tuns = mutableListOf<TunInput?>()

        override suspend fun validate(config: CompiledConfig): Outcome<Unit> = Outcome.Success(Unit)

        override suspend fun start(config: CompiledConfig, tun: TunInput?): Outcome<EngineSession> {
            payloads += config.payloadForEngine()
            tuns += tun
            return Outcome.Success(
                object : EngineSession {
                    override val compiled = config

                    override fun state() = EngineState.RUNNING

                    override fun stats() = TrafficStats(0, 0)

                    override suspend fun stop() = Unit
                },
            )
        }
    }

    @Test
    fun orchestratorStartsTheEngineWithoutFdAndWithAdapterSettings() = runBlocking {
        val multi = ir("valid-multi.json")
        val plan = CandidatePlanner.plan(multi, XrayBackend.CAPABILITIES, null, HealthBook(), null, 0)
        val engine = Recording()
        val log = Logger("t", MemoryLogSink(), clock::nowMillis)
        val report = ConnectionOrchestrator(XrayCompiler(dnsHijackAnyAddress = true), engine, { _, _ -> Outcome.Success(Unit) }, HealthBook(), clock, log) { }
            .connect(multi, plan, null, systemTun = system)
        assertIs<ConnectionReport.Connected>(report)
        assertNull(engine.tuns.single(), "fd TUN на Windows нет: адаптер создаёт ядро")
        val payload = engine.payloads.single()
        assertTrue("\"autoSystemRoutingTable\"" in payload && "\"172.19.0.1/30\"" in payload, "настройки адаптера — во входе TUN")
        // TUN платформы и TUN ядра вместе — ошибка вызова, а не два входа.
        val fd = TunInput(3, XrayBackend.TUN_MTU) { true }
        assertFailsWith<IllegalArgumentException> {
            ConnectionOrchestrator(XrayCompiler(), engine, { _, _ -> Outcome.Success(Unit) }, HealthBook(), clock, log) { }
                .connect(multi, plan, fd, systemTun = system)
        }
        assertEquals(1, engine.payloads.size)
    }
}
