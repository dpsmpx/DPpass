package com.dpsmpx.dppass.network

import com.dpsmpx.dppass.core.Clock

/**
 * Бюджет проб (D-14). Проверки сами — сигнал для фильтра: залп
 * параллельных рукопожатий к одному адресу по наблюдениям 2026 года
 * сам вызывает «заморозку» (`docs/research/RUSSIA_NETWORK_RESTRICTIONS.md`,
 * L7). Поэтому пробы идут **по одной**, с паузой не меньше
 * [minIntervalMillis] к одному ориентиру и не больше [maxPerWindow] за
 * окно [windowMillis].
 */
class ProbeBudget(
    private val clock: Clock,
    private val minIntervalMillis: Long = 1_500,
    private val maxPerWindow: Int = 12,
    private val windowMillis: Long = 60_000,
) {
    private val lastByTarget = HashMap<ProbeTarget, Long>()
    private val history = ArrayDeque<Long>()

    /** Можно ли сейчас пробу к [target]; если да — она засчитана. */
    @Synchronized
    fun tryAcquire(target: ProbeTarget): Boolean {
        val now = clock.nowMillis()
        while (history.isNotEmpty() && now - history.first() >= windowMillis) history.removeFirst()
        if (history.size >= maxPerWindow) return false
        val last = lastByTarget[target]
        if (last != null && now - last < minIntervalMillis) return false
        lastByTarget[target] = now
        history.addLast(now)
        return true
    }

    /**
     * Сколько ждать, пока в окне освободится место под [count] проб подряд
     * (0 — можно сейчас): проверка по кнопке не начинается, если её пробы
     * упрутся в предел и будут пропущены (D-60).
     */
    @Synchronized
    fun waitForMillis(count: Int): Long {
        val now = clock.nowMillis()
        while (history.isNotEmpty() && now - history.first() >= windowMillis) history.removeFirst()
        val excess = history.size + count - maxPerWindow
        if (excess <= 0) return 0
        if (count > maxPerWindow) return Long.MAX_VALUE
        return (history.elementAt(excess - 1) + windowMillis - now).coerceAtLeast(0)
    }

    /** Сколько ждать до следующей пробы к [target] (0 — можно сейчас). */
    @Synchronized
    fun waitMillis(target: ProbeTarget): Long {
        val now = clock.nowMillis()
        val last = lastByTarget[target] ?: return 0
        return (last + minIntervalMillis - now).coerceAtLeast(0)
    }
}

/**
 * Стандартный план оценки: от дешёвого к дорогому, отечественный
 * ориентир раньше зарубежного. Каждая проба — с причиной, зачем она.
 */
object ProbePlan {
    val STANDARD: List<ProbeRequest> = listOf(
        ProbeRequest(ProbeKind.CAPTIVE, ProbeTarget.DOMESTIC),
        ProbeRequest(ProbeKind.DNS, ProbeTarget.DOMESTIC),
        ProbeRequest(ProbeKind.TCP, ProbeTarget.DOMESTIC),
        ProbeRequest(ProbeKind.DNS, ProbeTarget.FOREIGN),
        ProbeRequest(ProbeKind.TCP, ProbeTarget.FOREIGN),
        ProbeRequest(ProbeKind.TLS, ProbeTarget.FOREIGN),
        ProbeRequest(ProbeKind.UDP, ProbeTarget.FOREIGN),
        ProbeRequest(ProbeKind.BULK, ProbeTarget.FOREIGN),
    )
}

/**
 * Последовательный прогон плана с бюджетом. Ожидание между пробами —
 * через [pause] (в тестах — без реального сна).
 */
class NetworkAssessor(
    private val prober: Prober,
    private val budget: ProbeBudget,
    private val pause: suspend (Long) -> Unit,
) {
    /** [onResult] — после каждой пробы: экран показывает исходы по мере появления. */
    suspend fun assess(
        type: NetworkType,
        plan: List<ProbeRequest> = ProbePlan.STANDARD,
        onResult: (ProbeResult) -> Unit = {},
    ): NetworkAssessment {
        val results = mutableListOf<ProbeResult>()
        if (type == NetworkType.NONE) return NetworkClassifier.classify(type, results)
        for (request in plan) {
            val wait = budget.waitMillis(request.target)
            if (wait > 0) pause(wait)
            val result = if (budget.tryAcquire(request.target)) prober.probe(request) else ProbeResult(request, ProbeOutcome.SKIPPED)
            results += result
            onResult(result)
            // Перехват страницей входа: дальше мерить бессмысленно.
            if (request.kind == ProbeKind.CAPTIVE && result.outcome == ProbeOutcome.REDIRECTED) break
        }
        return NetworkClassifier.classify(type, results)
    }
}

/**
 * Эвристика «наблюдения → класс». Правила — в таблице тестов
 * (`NetworkClassifierTest`) и в `docs/ARCHITECTURE.md`, «Сеть»; каждое
 * срабатывание оставляет строку в [NetworkAssessment.evidence].
 */
object NetworkClassifier {
    fun classify(type: NetworkType, results: List<ProbeResult>): NetworkAssessment {
        val evidence = mutableListOf<String>()
        fun of(kind: ProbeKind, target: ProbeTarget) = results.firstOrNull { it.request.kind == kind && it.request.target == target }
        fun reach(r: ProbeResult?): Reachability = when (r?.outcome) {
            null, ProbeOutcome.SKIPPED, ProbeOutcome.INCONCLUSIVE -> Reachability.UNKNOWN
            ProbeOutcome.SUCCESS -> Reachability.OK
            ProbeOutcome.STALLED, ProbeOutcome.DNS_TAMPERED -> Reachability.DEGRADED
            else -> Reachability.BLOCKED
        }

        if (type == NetworkType.NONE) {
            return NetworkAssessment(type, Reachability.UNKNOWN, Reachability.UNKNOWN, Reachability.UNKNOWN, Reachability.UNKNOWN,
                Reachability.UNKNOWN, false, RestrictionClass.OFFLINE, Confidence.HIGH, listOf("система сообщает: сети нет"))
        }

        val captive = of(ProbeKind.CAPTIVE, ProbeTarget.DOMESTIC)?.outcome == ProbeOutcome.REDIRECTED
        val domesticDns = reach(of(ProbeKind.DNS, ProbeTarget.DOMESTIC))
        val domesticTcp = reach(of(ProbeKind.TCP, ProbeTarget.DOMESTIC))
        val dns = reach(of(ProbeKind.DNS, ProbeTarget.FOREIGN))
        val tcp = reach(of(ProbeKind.TCP, ProbeTarget.FOREIGN))
        val tls = reach(of(ProbeKind.TLS, ProbeTarget.FOREIGN))
        val udp = reach(of(ProbeKind.UDP, ProbeTarget.FOREIGN))
        val bulk = reach(of(ProbeKind.BULK, ProbeTarget.FOREIGN))
        val known = results.count { it.outcome != ProbeOutcome.SKIPPED && it.outcome != ProbeOutcome.INCONCLUSIVE }

        fun result(cls: RestrictionClass, conf: Confidence) =
            NetworkAssessment(type, dns, tcp, tls, udp, bulk, captive, cls, conf, evidence.toList())

        if (captive) {
            evidence += "HTTP-проверка перенаправлена — страница входа"
            return result(RestrictionClass.CAPTIVE, Confidence.HIGH)
        }
        val foreign = listOf(dns, tcp, tls)
        val domesticOk = domesticTcp == Reachability.OK || domesticDns == Reachability.OK
        val foreignAllBlocked = foreign.all { it == Reachability.BLOCKED }

        if (!domesticOk && domesticTcp != Reachability.UNKNOWN && foreign.none { it == Reachability.OK || it == Reachability.DEGRADED }) {
            evidence += "нет ответа ни от отечественного, ни от зарубежного ориентира"
            return result(RestrictionClass.OFFLINE, if (foreignAllBlocked) Confidence.HIGH else Confidence.MEDIUM)
        }
        if (domesticOk && foreignAllBlocked) {
            evidence += "отечественный ориентир доступен, зарубежный — нет ни по DNS, ни по TCP, ни по TLS"
            return result(RestrictionClass.ALLOWLIST_LIKE, if (udp == Reachability.BLOCKED) Confidence.HIGH else Confidence.MEDIUM)
        }
        if (known < 4) {
            evidence += "проведено проб: $known — мало для вывода"
            return result(RestrictionClass.UNKNOWN, Confidence.LOW)
        }
        // Без зарубежных TCP и TLS «ограничений не видно» не вывод, а пропуск (D-60, 17.10.2026).
        if (tcp == Reachability.UNKNOWN && tls == Reachability.UNKNOWN) {
            evidence += "зарубежные TCP и TLS не проверены — мало для вывода"
            return result(RestrictionClass.UNKNOWN, Confidence.LOW)
        }
        val degraded = mutableListOf<String>()
        if (dns != Reachability.OK && dns != Reachability.UNKNOWN) degraded += "DNS к зарубежному имени: $dns"
        if (tcp == Reachability.OK && tls != Reachability.OK && tls != Reachability.UNKNOWN) degraded += "TCP проходит, TLS — $tls"
        if (tcp == Reachability.BLOCKED && domesticOk) degraded += "зарубежный адрес не отвечает по TCP"
        if (bulk == Reachability.DEGRADED) degraded += "крупная передача остановилась (порог 16–20 КБ)"
        val latencies = results.filter { it.ok && it.request.target == ProbeTarget.FOREIGN }.mapNotNull { it.latencyMillis }.sorted()
        if (latencies.isNotEmpty() && latencies[latencies.size / 2] > HIGH_LATENCY_MILLIS) {
            degraded += "высокая задержка: медиана ${latencies[latencies.size / 2]} мс"
        }
        if (udp == Reachability.BLOCKED && tcp == Reachability.OK) evidence += "UDP не проходит при рабочем TCP"
        if (degraded.isNotEmpty()) {
            evidence += degraded
            return result(RestrictionClass.DEGRADED, if (degraded.size >= 2) Confidence.HIGH else Confidence.MEDIUM)
        }
        // «Все» — только если ни одна зарубежная проба не пропущена и не осталась без вывода.
        val untested = listOf(dns, tcp, tls, udp, bulk).any { it == Reachability.UNKNOWN }
        evidence += when {
            udp == Reachability.BLOCKED -> "остальные пробы прошли"
            untested -> "проведённые пробы прошли, часть не проверена"
            else -> "все пробы прошли"
        }
        return result(RestrictionClass.NORMAL, if (untested) Confidence.MEDIUM else Confidence.HIGH)
    }

    const val HIGH_LATENCY_MILLIS: Long = 1_500
}
