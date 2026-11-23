package com.dpsmpx.dppass.engine.xray

import com.dpsmpx.dppass.engine.Zapret2ProbeCatalog

/**
 * Separate service-component evidence. A verified homepage does not imply
 * usable browse API, thumbnails or Googlevideo media, and API 4xx never
 * qualifies as feed success. No candidate from this report trains AUTO.
 */
object Zapret2ServiceReport {
    data class Result(
        val target: String,
        val method: String,
        val successful: Int,
        val attempted: Int,
        val stable: Boolean,
        val meanSuccessMs: Long?,
    )

    fun isSuccess(target: String, probe: Zapret2GoogleProbe): Boolean = when(target) {
        "service_youtube_home" ->
            probe.outcome == "ok" && probe.httpStatus in 200..299 &&
                probe.bodyBytes > 0
        "service_youtube_api" ->
            probe.outcome == "http_reachable" && probe.httpStatus in 200..499
        "service_youtube_thumbnail" ->
            probe.outcome == "ok" && probe.httpStatus in 200..299 &&
                probe.bodyBytes >= 128
        else -> false
    }

    fun summarize(rows: List<Zapret2GoogleAttempt>): List<Result> =
        Zapret2ProbeCatalog.serviceTargets.flatMap { target ->
            Zapret2ProbeCatalog.serviceStrategies.map { method ->
                val expected = (1..Zapret2ProbeCatalog.SERVICE_REPEATS).map { attempt ->
                    rows.filter { it.target == target && it.strategy == method &&
                        it.attempt == attempt }
                }
                var success = 0
                var elapsed = 0L
                val complete = expected.all { it.size == 1 }
                expected.forEach { matches ->
                    val row = matches.singleOrNull() ?: return@forEach
                    if (isSuccess(target, row.result)) {
                        success++
                        elapsed += row.result.elapsedMillis
                    }
                }
                Result(target, method, success,
                    expected.count { it.size == 1 },
                    complete && success == Zapret2ProbeCatalog.SERVICE_REPEATS,
                    if (success > 0) elapsed / success else null)
            }
        }

    fun render(network: String, rows: List<Zapret2GoogleAttempt>): String = buildString {
        val results = summarize(rows)
        appendLine("=== DPpass — независимая проверка компонентов YouTube ===")
        appendLine("Сеть: $network")
        appendLine("Protected Xray TCP/443, оригинальный Host/SNI, сертификаты проверяются.")
        appendLine("DNS: текущий защищённый исходящий путь Xray; не закреплён отдельным DoH в этом тесте.")
        appendLine("Каждый фиксированный компонент: 3 независимые попытки на метод.")
        appendLine("Кандидаты: plain, tlsrec-split, fake-5; глобальный DNS/VPN/AUTO не изменяются.")
        for (target in Zapret2ProbeCatalog.serviceTargets) {
            val label = Zapret2ProbeCatalog.targetLabel(target)
            appendLine()
            appendLine("$label")
            if (target == "service_youtube_api") {
                appendLine("API: HTTP 2xx/4xx подтверждает TLS+HTTP транспорт, не пригодность ленты.")
            } else if (target == "service_youtube_thumbnail") {
                appendLine("Thumbnail: фиксированный JPEG; это не поток googlevideo.com.")
            } else {
                appendLine("Главная: валидный HTML не доказывает работу приложения YouTube.")
            }
            for (entry in results.filter { it.target == target }) {
                appendLine("  ${entry.method}: ${entry.successful}/${entry.attempted}" +
                    " verified; stable=${entry.stable}; mean_success_ms=${entry.meanSuccessMs ?: "-"}")
            }
            val confirmed = results.filter { it.target == target && it.stable }
            val best = confirmed.minWithOrNull(
                compareBy<Result>({ it.meanSuccessMs ?: Long.MAX_VALUE }, { it.method }))
            appendLine("  Лучший подтверждённый метод: ${best?.method ?: "-"}" +
                if (target == "service_youtube_api") " (только транспорт)" else "")
        }
        appendLine()
        appendLine("Составная проверка:")
        for (target in Zapret2ProbeCatalog.serviceTargets) {
            val result = results.any { it.target == target && it.stable }
            appendLine("  ${Zapret2ProbeCatalog.targetLabel(target)}: " +
                if (result) "есть повторяемый путь 3/3" else "устойчивый путь не подтверждён")
        }
        appendLine("AUTO: not_applied — этот тест диагностический, он не обучает маршруты.")
        appendLine("HTTP3/QUIC, контент feed, авторизованная работа API и воспроизведение видео не проверены.")
        appendLine("Адреса, запросы пользователя, cookie, ключи и тела ответов в отчёт не включены.")
    }
}
