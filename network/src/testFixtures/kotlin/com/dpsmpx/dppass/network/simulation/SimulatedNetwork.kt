package com.dpsmpx.dppass.network.simulation

import com.dpsmpx.dppass.network.ProbeKind
import com.dpsmpx.dppass.network.ProbeOutcome
import com.dpsmpx.dppass.network.ProbeRequest
import com.dpsmpx.dppass.network.ProbeResult
import com.dpsmpx.dppass.network.ProbeTarget
import com.dpsmpx.dppass.network.Prober

/**
 * Искусственные сетевые условия (`docs/TESTING.md`, «Модель сети»).
 *
 * Это **синтетические классы** из `docs/research/RUSSIA_NETWORK_RESTRICTIONS.md`,
 * а не снимки конкретного оператора: модель нужна, чтобы проверять
 * классификацию и политику подключения детерминированно. Инструмент
 * тестов и демонстрации (`cli`); в рабочих путях приложения не
 * используется (`tools/hostcheck/check_modules.py`).
 */
enum class NetworkCondition {
    NORMAL,
    DNS_BLOCKED,
    DNS_DEGRADED,
    IP_BLOCKED,
    TCP_REACHABLE_UDP_BLOCKED,
    TLS_DEGRADED,
    HIGH_LATENCY,
    PACKET_LOSS,
    CAPTIVE_PORTAL,
    ALLOWLIST_LIKE,
    FULL_ENDPOINT_BLOCK,

    /**
     * Закрыты адреса одного поставщика (L4): ориентир сети доставки сбрасывает
     * соединения, второй зарубежный и серверы вне [SimulatedNetwork.blockedEndpoints]
     * работают (D-62; телефон, 17.10.2026).
     */
    PROVIDER_BLOCKED,
    OFFLINE,
}

/** Класс пути кандидата, как его видит модель (без зависимости от config). */
enum class PathClass { TCP_STREAM, HTTP_CDN, UDP_QUIC }

class SimulatedNetwork(
    val condition: NetworkCondition,
    /** Адреса, заблокированные по IP (для [NetworkCondition.IP_BLOCKED]). */
    private val blockedEndpoints: Set<String> = emptySet(),
) : Prober {
    /** Сколько проб выполнено — тесты бюджета проверяют, что нет «залпов». */
    var probeCount: Int = 0
        private set

    override suspend fun probe(request: ProbeRequest): ProbeResult {
        probeCount++
        return ProbeResult(request, outcome(request), latency(request))
    }

    private fun latency(request: ProbeRequest): Long = when (condition) {
        NetworkCondition.HIGH_LATENCY -> 2_500
        else -> if (request.target == ProbeTarget.DOMESTIC) 20 else 60
    }

    private fun outcome(r: ProbeRequest): ProbeOutcome {
        val foreign = r.target != ProbeTarget.DOMESTIC
        return when (condition) {
            // IP_BLOCKED и FULL_ENDPOINT_BLOCK бьют по адресам серверов, а не по ориентирам проб
            NetworkCondition.NORMAL, NetworkCondition.HIGH_LATENCY, NetworkCondition.IP_BLOCKED, NetworkCondition.FULL_ENDPOINT_BLOCK ->
                ProbeOutcome.SUCCESS
            NetworkCondition.DNS_BLOCKED -> if (foreign && r.kind == ProbeKind.DNS) ProbeOutcome.DNS_TAMPERED else ProbeOutcome.SUCCESS
            NetworkCondition.DNS_DEGRADED -> if (foreign && r.kind == ProbeKind.DNS) ProbeOutcome.TIMEOUT else ProbeOutcome.SUCCESS
            NetworkCondition.TCP_REACHABLE_UDP_BLOCKED -> if (r.kind == ProbeKind.UDP) ProbeOutcome.TIMEOUT else ProbeOutcome.SUCCESS
            NetworkCondition.TLS_DEGRADED -> when {
                foreign && r.kind == ProbeKind.TLS -> ProbeOutcome.RESET
                foreign && r.kind == ProbeKind.BULK -> ProbeOutcome.STALLED
                else -> ProbeOutcome.SUCCESS
            }
            NetworkCondition.PACKET_LOSS -> when {
                foreign && r.kind == ProbeKind.TLS -> ProbeOutcome.TIMEOUT
                foreign && r.kind == ProbeKind.BULK -> ProbeOutcome.STALLED
                else -> ProbeOutcome.SUCCESS
            }
            NetworkCondition.CAPTIVE_PORTAL -> if (r.kind == ProbeKind.CAPTIVE) ProbeOutcome.REDIRECTED else ProbeOutcome.TIMEOUT
            NetworkCondition.ALLOWLIST_LIKE -> if (foreign) ProbeOutcome.TIMEOUT else ProbeOutcome.SUCCESS
            NetworkCondition.OFFLINE -> ProbeOutcome.TIMEOUT
            NetworkCondition.PROVIDER_BLOCKED -> when {
                r.target != ProbeTarget.FOREIGN || r.kind == ProbeKind.DNS -> ProbeOutcome.SUCCESS
                r.kind == ProbeKind.UDP -> ProbeOutcome.TIMEOUT
                else -> ProbeOutcome.REFUSED
            }
        }
    }

    /**
     * Что увидит соединение кандидата: [ProbeOutcome.SUCCESS] — полезная
     * нагрузка идёт; [ProbeOutcome.STALLED] — «подключено, но данных
     * нет» (L7); остальное — отказ на своём шаге.
     */
    fun candidatePath(path: PathClass, endpoint: String, reachableUnderAllowlist: Boolean): ProbeOutcome = when (condition) {
        NetworkCondition.NORMAL, NetworkCondition.HIGH_LATENCY, NetworkCondition.DNS_BLOCKED, NetworkCondition.DNS_DEGRADED -> ProbeOutcome.SUCCESS
        NetworkCondition.IP_BLOCKED -> if (endpoint in blockedEndpoints) ProbeOutcome.TIMEOUT else ProbeOutcome.SUCCESS
        NetworkCondition.PROVIDER_BLOCKED -> if (endpoint in blockedEndpoints) ProbeOutcome.REFUSED else ProbeOutcome.SUCCESS
        NetworkCondition.TCP_REACHABLE_UDP_BLOCKED -> if (path == PathClass.UDP_QUIC) ProbeOutcome.TIMEOUT else ProbeOutcome.SUCCESS
        NetworkCondition.TLS_DEGRADED -> if (path == PathClass.TCP_STREAM) ProbeOutcome.STALLED else ProbeOutcome.SUCCESS
        NetworkCondition.PACKET_LOSS -> if (path == PathClass.UDP_QUIC) ProbeOutcome.SUCCESS else ProbeOutcome.STALLED
        NetworkCondition.CAPTIVE_PORTAL -> ProbeOutcome.REDIRECTED
        NetworkCondition.ALLOWLIST_LIKE -> if (reachableUnderAllowlist) ProbeOutcome.SUCCESS else ProbeOutcome.TIMEOUT
        NetworkCondition.FULL_ENDPOINT_BLOCK -> ProbeOutcome.TIMEOUT
        NetworkCondition.OFFLINE -> ProbeOutcome.UNREACHABLE
    }
}
