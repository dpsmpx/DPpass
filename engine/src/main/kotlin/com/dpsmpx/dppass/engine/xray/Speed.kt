package com.dpsmpx.dppass.engine.xray

import com.dpsmpx.dppass.diagnostics.DiagCode
import com.dpsmpx.dppass.diagnostics.Diagnostic
import com.dpsmpx.dppass.diagnostics.ErrorSummary
import com.dpsmpx.dppass.diagnostics.Outcome
import com.dpsmpx.dppass.diagnostics.Redactor
import kotlin.math.abs

/**
 * Итог замера через туннель (D-61). Пинг — медиана времени ответа на малый
 * запрос (до заголовков ответа, по уже открытому соединению); jitter —
 * среднее модулей разностей соседних пингов (так считают измерители
 * скорости; RFC 3550 сглаживает поток, а здесь десять замеров); скорость —
 * биты тела загрузки за время её передачи.
 */
data class SpeedReport(
    val pingMillis: Double,
    val minPingMillis: Double,
    val jitterMillis: Double,
    val downloadBitsPerSecond: Long,
    val receivedBytes: Long,
    val transferMillis: Long,
    val pings: Int,
    /**
     * Данные встали (L7): последний байт пришёл через столько мс от начала
     * загрузки, а дальше до конца срока — ни байта (не меньше
     * [XraySpeed.STALL_GAP_MILLIS]). null — шли до конца. Тогда средняя
     * [downloadBitsPerSecond] — не скорость канала, а «сколько пустили».
     */
    val stalledAfterMillis: Long? = null,
    /** Скорость до остановки: тело за время до последнего байта; при `stalledAfterMillis == null` — та же, что средняя. */
    val activeBitsPerSecond: Long = downloadBitsPerSecond,
)

/** Замер через туннель на ядре Xray (D-61): цель, пределы и итог. */
object XraySpeed {
    /** Адрес с заданным объёмом ответа (`?bytes=N`) — тот же ориентир, что у пробы сети (D-60). */
    const val TARGET: String = "https://speed.cloudflare.com/__down"
    const val PINGS: Int = 10

    /** Предел загрузки: на мобильной сети международный трафик сверх лимита платный. */
    const val MAX_BYTES: Long = 25L * 1024 * 1024
    const val MAX_TIME_MILLIS: Int = 8_000
    const val TIMEOUT_MILLIS: Int = 25_000

    /** Тишина до конца срока, после которой загрузка считается вставшей, а не медленной. */
    const val STALL_GAP_MILLIS: Long = 2_000
    private const val CORE_TEXT_LIMIT = 2_000

    fun report(r: SpeedProbeResult, redactor: Redactor = Redactor()): Outcome<SpeedReport> {
        val (code, message) = when (r.outcome) {
            DnsProbeOutcome.OK -> return Outcome.Success(summary(r))
            DnsProbeOutcome.UNREACHABLE -> DiagCode.ENDPOINT_UNREACHABLE to "через сервер профиля не пришло ни байта: замер не начался"
            DnsProbeOutcome.TLS -> DiagCode.TLS_HANDSHAKE_FAILED to "TLS с адресом замера через сервер профиля не установлен"
            DnsProbeOutcome.STALLED -> DiagCode.PAYLOAD_STALLED to "соединение через сервер есть, но данные замера за срок не пришли"
            DnsProbeOutcome.BAD_ANSWER -> DiagCode.HEALTH_CHECK_FAILED to "адрес замера ответил не тем, что ждали"
            DnsProbeOutcome.NOT_RUNNING -> DiagCode.HEALTH_CHECK_FAILED to "туннель не поднят — мерить нечего"
            DnsProbeOutcome.CONTRACT -> DiagCode.HEALTH_CHECK_FAILED to "мост не понял замер"
        }
        val d = Diagnostic.error(code, message)
        return Outcome.failure(
            if (r.text.isEmpty()) d else d.withCause(Diagnostic(code, "замер", error = ErrorSummary("xray", redactor.redact(r.text.take(CORE_TEXT_LIMIT))))),
        )
    }

    internal fun summary(r: SpeedProbeResult): SpeedReport {
        val ms = r.pingMicros.map { it / 1000.0 }
        val sorted = ms.sorted()
        val median = when {
            sorted.isEmpty() -> 0.0
            sorted.size % 2 == 1 -> sorted[sorted.size / 2]
            else -> (sorted[sorted.size / 2 - 1] + sorted[sorted.size / 2]) / 2
        }
        val jitter = if (ms.size < 2) 0.0 else ms.zipWithNext { a, b -> abs(b - a) }.average()
        val bps = if (r.transferMicros <= 0) 0 else r.receivedBytes * 8 * 1_000_000 / r.transferMicros
        val stalled = r.receivedBytes > 0 && r.lastByteMicros > 0 && r.transferMicros - r.lastByteMicros >= STALL_GAP_MILLIS * 1000
        val active = if (stalled) r.receivedBytes * 8 * 1_000_000 / r.lastByteMicros else bps
        return SpeedReport(
            median, sorted.firstOrNull() ?: 0.0, jitter, bps, r.receivedBytes, r.transferMicros / 1000, ms.size,
            stalledAfterMillis = if (stalled) r.lastByteMicros / 1000 else null,
            activeBitsPerSecond = active,
        )
    }
}
