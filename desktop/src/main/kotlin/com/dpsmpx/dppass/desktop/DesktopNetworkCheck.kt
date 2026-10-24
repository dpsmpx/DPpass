package com.dpsmpx.dppass.desktop

import com.dpsmpx.dppass.connection.RegimeMemory
import com.dpsmpx.dppass.core.Clock
import com.dpsmpx.dppass.diagnostics.Logger
import com.dpsmpx.dppass.diagnostics.Outcome
import com.dpsmpx.dppass.diagnostics.Safe
import com.dpsmpx.dppass.network.NetworkAssessment
import com.dpsmpx.dppass.network.NetworkAssessor
import com.dpsmpx.dppass.network.NetworkType
import com.dpsmpx.dppass.network.ProbeBudget
import com.dpsmpx.dppass.network.ProbeOutcome
import com.dpsmpx.dppass.network.ProbePlan
import com.dpsmpx.dppass.network.ProbeResult
import com.dpsmpx.dppass.network.Prober
import com.dpsmpx.dppass.network.QuietWindow
import com.dpsmpx.dppass.network.SocketProber
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.withContext
import java.security.SecureRandom
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Проверка сети на ПК (D-79, к D-60 и D-64): те же пробы и бюджет D-14, что
 * на Android, — мимо туннеля ([LinuxProbeNetwork]). Одна за раз; итог — в
 * окно и в журнал без адресов, в план — только через память режима (D-64).
 * Пока идёт проверка и [QUIET_AFTER_MILLIS] после, наблюдатель сеанса (D-78)
 * пробы не начинает, а начатую не учитывает: нагрузка проверки — не
 * деградация сервера (T14).
 */
class DesktopNetworkCheck(
    private val log: Logger,
    private val probeNetwork: LinuxProbeNetwork,
    /** Сеть ПК сейчас; null — маршрута по умолчанию нет. */
    private val network: () -> LinuxNetwork? = LinuxNetwork::current,
    private val prober: (LinuxProbeNetwork) -> Prober = { SocketProber(it, Clock.MONOTONIC, SecureRandom()) },
    clock: Clock = Clock.MONOTONIC,
    private val pause: suspend (Long) -> Unit = { delay(it) },
) {
    private val checking = AtomicBoolean(false)

    /** Один на процесс: две проверки подряд упираются в предел, а не дают залп (D-14). */
    private val budget = ProbeBudget(clock)
    private val quiet = QuietWindow(clock, QUIET_AFTER_MILLIS)
    private val regime = RegimeMemory(clock)

    fun busy(): Boolean = checking.get()

    /** Через сколько мс полная проверка уложится в бюджет (0 — сейчас). */
    fun readyInMillis(): Long = budget.waitForMillis(ProbePlan.STANDARD.size)

    /** Проба наблюдателя сейчас мерила бы проверку, а не сервер. */
    fun probesQuiet(): Boolean = quiet.active()

    /** Белый список по свежей проверке в нынешней сети; null — режим неизвестен. */
    fun regime(): NetworkAssessment? = regime.allowlist(network()?.key)

    /** Опровергнут (подключился сервер, который под списком отказывал): режим снова неизвестен. */
    fun forgetRegime() = regime.forget()

    /**
     * Проверить сеть. Отказ — проверке не пустить пробы мимо туннеля
     * (`NETWORK_CHECK_UNAVAILABLE`); null — уже идёт другая проверка.
     */
    suspend fun run(onResult: (ProbeResult) -> Unit = {}): Outcome<NetworkAssessment>? = withContext(Dispatchers.IO) {
        if (!checking.compareAndSet(false, true)) return@withContext null
        quiet.begin()
        try {
            assess(onResult)
        } finally {
            quiet.end()
            checking.set(false)
        }
    }

    private suspend fun assess(onResult: (ProbeResult) -> Unit): Outcome<NetworkAssessment> {
        probeNetwork.ready()?.let {
            log.diagnostic(it)
            return Outcome.failure(it)
        }
        val net = network()
        val type = net?.type ?: NetworkType.NONE
        val probes = if (net == null) Prober { ProbeResult(it, ProbeOutcome.UNREACHABLE) } else prober(probeNetwork)
        log.info("network_check", "type" to type, "trigger" to Safe("BUTTON"))
        val assessment = NetworkAssessor(probes, budget, pause).assess(type) { r ->
            log.info("network_probe", "kind" to r.request.kind, "target" to r.request.target, "outcome" to r.outcome, "ms" to r.latencyMillis)
            onResult(r)
        }
        log.info("network_assessed", "type" to assessment.type, "class" to assessment.restriction, "confidence" to assessment.confidence)
        // Итог — в память режима этой сети (D-64), любой: «не белый список» тоже сведение. Сеть в журнал не идёт.
        net?.let { regime.remember(assessment, it.key) }
        assessment.evidence.forEach { log.info("network_evidence", "text" to Safe(it)) }
        return Outcome.Success(assessment)
    }

    companion object {
        /** Как у Android: очередь в канале после проб — секунды. */
        const val QUIET_AFTER_MILLIS: Long = 15_000
    }
}
