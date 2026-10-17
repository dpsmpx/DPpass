package com.dpsmpx.dppass.network

/**
 * Модель наблюдений о сети (D-14). Модуль не знает ни про ядро, ни про
 * конфигурацию: он отвечает на вопрос «что сейчас пропускает эта сеть»,
 * а не «какой сервер выбрать».
 */
enum class NetworkType { WIFI, MOBILE, ETHERNET, OTHER, NONE }

enum class ProbeKind {
    /** DNS-запрос к резолверу сети. */
    DNS,

    /** Установка TCP-соединения. */
    TCP,

    /** TLS-рукопожатие с безобидным SNI. */
    TLS,

    /** UDP-обмен (QUIC-подобный). */
    UDP,

    /** HTTP-проверка на перехват (captive portal). */
    CAPTIVE,

    /** Передача больше 32 КБ в одном соединении (порог «16–20 КБ», L4/L7). */
    BULK,
}

/**
 * Куда проба. Отечественный и зарубежный ориентиры нужны, чтобы
 * отличить «нет связи вообще» (L10) от «пускают только внутрь» (L9).
 */
enum class ProbeTarget {
    DOMESTIC,

    /** Зарубежный ориентир у сети доставки (D-60): там же крупная передача. */
    FOREIGN,

    /**
     * Второй зарубежный ориентир — у другого поставщика (D-62): отличает
     * «закрыты адреса одного поставщика» (L4) от «закрыто всё зарубежное» (L9).
     */
    FOREIGN_ALT,
}

enum class ProbeOutcome {
    SUCCESS,
    TIMEOUT,
    RESET,
    REFUSED,

    /** Ответ DNS подменён или NXDOMAIN для существующего имени. */
    DNS_TAMPERED,

    /** Передача остановилась на характерном объёме. */
    STALLED,

    /** HTTP перенаправлен на страницу входа. */
    REDIRECTED,
    UNREACHABLE,

    /** Пробу не дал провести бюджет — это не наблюдение о сети. */
    SKIPPED,

    /**
     * Проба прошла, но о сети ничего не сказала: ориентир ответил не тем
     * (не 2xx), или о странице входа система не знает (D-60).
     */
    INCONCLUSIVE,
}

data class ProbeRequest(val kind: ProbeKind, val target: ProbeTarget)

data class ProbeResult(
    val request: ProbeRequest,
    val outcome: ProbeOutcome,
    val latencyMillis: Long? = null,
) {
    val ok: Boolean get() = outcome == ProbeOutcome.SUCCESS
}

/** Исполнитель проб: на сокетах — [SocketProber] (D-60); в тестах — `SimulatedNetwork` (тестовая фикстура). */
fun interface Prober {
    suspend fun probe(request: ProbeRequest): ProbeResult
}

enum class Reachability { OK, DEGRADED, BLOCKED, UNKNOWN }

/**
 * Класс ограничений сети на данный момент — эвристика по наблюдениям,
 * **не знание о политике оператора** (D-14).
 */
enum class RestrictionClass {
    /** Данных мало для вывода. */
    UNKNOWN,
    NORMAL,

    /** Что-то режется (DNS, TLS, крупные передачи), но путь наружу есть. */
    DEGRADED,

    /** Внутрь страны можно, наружу — нет: похоже на белый список (L9). */
    ALLOWLIST_LIKE,

    /** Перехват страницей входа. */
    CAPTIVE,

    /** Связи нет ни с чем (L10 или нет сети). */
    OFFLINE,
}

enum class Confidence { LOW, MEDIUM, HIGH }

data class NetworkAssessment(
    val type: NetworkType,
    val dns: Reachability,
    val tcp: Reachability,
    val tls: Reachability,
    val udp: Reachability,
    val bulk: Reachability,
    val captivePortal: Boolean,
    val restriction: RestrictionClass,
    val confidence: Confidence,
    /** Почему сделан вывод — по одной строке на наблюдение. */
    val evidence: List<String>,
)
