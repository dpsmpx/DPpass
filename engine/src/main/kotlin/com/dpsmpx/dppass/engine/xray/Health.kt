package com.dpsmpx.dppass.engine.xray

import com.dpsmpx.dppass.diagnostics.DiagCode
import com.dpsmpx.dppass.diagnostics.Diagnostic
import com.dpsmpx.dppass.diagnostics.ErrorSummary
import com.dpsmpx.dppass.diagnostics.Outcome
import com.dpsmpx.dppass.diagnostics.Redactor
import com.dpsmpx.dppass.routing.DnsPolicy
import com.dpsmpx.dppass.routing.DnsRoute
import com.dpsmpx.dppass.routing.DnsServer
import com.dpsmpx.dppass.routing.DnsTransport

/**
 * Проверка здоровья на ядре Xray (D-15, D-32): один запрос DNS через сервер
 * профиля к DNS-серверу конфигурации, который идёт через туннель. Ответ
 * пришёл — данные прошли через сервер туда и обратно; новых связей со
 * сторонними серверами нет (D-12).
 *
 * Сервер для пробы — сервер по умолчанию, если он идёт через туннель,
 * иначе первый такой в списке. DoT ядро не умеет (`XrayCompiler`),
 * поэтому сервер DoT для пробы не годится. Такого сервера нет — здоровье
 * не проверено, и это предупреждение `HEALTH_CHECK_SKIPPED`, а не молчаливый
 * успех.
 */
object XrayHealth {
    /** Сервер и цель пробы для моста (`https://…`, `udp://хост:порт`, `tcp://хост:порт`); null — проверить не через что. */
    fun target(dns: DnsPolicy): Pair<DnsServer, String>? {
        val tunnel = dns.servers.filter { it.route == DnsRoute.TUNNEL && wire(it.transport) != null }
        val chosen = tunnel.firstOrNull { it.id == dns.defaultServerId } ?: tunnel.firstOrNull() ?: return null
        return chosen to wire(chosen.transport)!!
    }

    private fun wire(t: DnsTransport): String? = when (t) {
        is DnsTransport.Https -> t.url
        is DnsTransport.Udp -> "udp://${t.server}"
        is DnsTransport.Tcp -> "tcp://${t.server}"
        is DnsTransport.Tls, DnsTransport.System -> null
    }

    /**
     * Исход пробы → результат проверки здоровья. Текст моста — причина
     * после [Redactor]: в нём может быть адрес сервера DoH с личным путём.
     */
    fun outcome(server: DnsServer, r: DnsProbeResult, redactor: Redactor = Redactor()): Outcome<Unit> {
        val who = "DNS-сервер «${server.id}»"
        val (code, message) = when (r.outcome) {
            DnsProbeOutcome.OK -> return Outcome.Success(Unit)
            DnsProbeOutcome.UNREACHABLE ->
                DiagCode.ENDPOINT_UNREACHABLE to
                    "через сервер профиля за ${r.elapsedMillis} мс не пришло ни байта ($who): сервер недоступен или отверг соединение"
            DnsProbeOutcome.TLS ->
                DiagCode.TLS_HANDSHAKE_FAILED to
                    "TLS с $who через сервер профиля не установлен"
            DnsProbeOutcome.STALLED ->
                DiagCode.PAYLOAD_STALLED to
                    "соединение через сервер есть (${r.receivedBytes} байт), но ответа ($who) за ${r.elapsedMillis} мс нет"
            DnsProbeOutcome.BAD_ANSWER ->
                DiagCode.HEALTH_CHECK_FAILED to
                    "$who ответил через сервер профиля не ответом DNS"
            DnsProbeOutcome.NOT_RUNNING -> DiagCode.HEALTH_CHECK_FAILED to "ядро не запущено — проверять нечего"
            DnsProbeOutcome.CONTRACT -> DiagCode.HEALTH_CHECK_FAILED to "мост не понял цель пробы ($who)"
        }
        val d = Diagnostic.error(code, message)
        return Outcome.failure(
            if (r.text.isEmpty()) {
                d
            } else {
                d.withCause(Diagnostic(code, "проба DNS", error = ErrorSummary("xray", redactor.redact(r.text.take(CORE_TEXT_LIMIT)))))
            },
        )
    }

    /** Через туннель нет DNS-сервера, который годится для пробы. */
    fun skipped(): Outcome<Unit> = Outcome.Success(
        Unit,
        listOf(
            Diagnostic.warning(
                DiagCode.HEALTH_CHECK_SKIPPED,
                "здоровье не проверено: в DNS конфигурации нет сервера DoH, UDP или TCP через туннель — проверке не через что пройти (D-32)",
            ),
        ),
    )
}
