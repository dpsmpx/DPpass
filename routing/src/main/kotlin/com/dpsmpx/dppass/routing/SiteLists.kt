package com.dpsmpx.dppass.routing

import com.dpsmpx.dppass.core.Cidr
import com.dpsmpx.dppass.core.Host
import com.dpsmpx.dppass.core.IpAddress
import com.dpsmpx.dppass.diagnostics.DiagCode
import com.dpsmpx.dppass.diagnostics.Diagnostic
import com.dpsmpx.dppass.diagnostics.Outcome

/** Что делать с сайтами своего списка (D-93). */
enum class SiteListKind(val wire: String, val action: RouteAction) {
    DIRECT("direct", RouteAction.DIRECT),
    PROXY("proxy", RouteAction.PROXY),
    BLOCK("block", RouteAction.BLOCK),
}

/**
 * Одна запись своего списка (D-93) — так, как её пишет пользователь:
 * `example.com` (с поддоменами), `full:example.com` (только это имя),
 * `keyword:text` (имя содержит), `geosite:код`, `1.2.3.4`, `10.0.0.0/8`,
 * `2001:db8::/32`, `geoip:код`. [text] — нормальная форма: по ней
 * сравниваются записи и пишется хранилище.
 */
sealed interface SiteEntry {
    val text: String

    data class Domain(val name: String) : SiteEntry {
        override val text: String get() = name
    }

    data class Full(val name: String) : SiteEntry {
        override val text: String get() = "full:$name"
    }

    data class Keyword(val keyword: String) : SiteEntry {
        override val text: String get() = "keyword:$keyword"
    }

    data class GeoSite(val code: String) : SiteEntry {
        override val text: String get() = "geosite:$code"
    }

    data class Address(val cidr: Cidr) : SiteEntry {
        override val text: String get() = if (cidr.prefix == cidr.network.bitLength) cidr.network.toString() else cidr.toString()
    }

    data class GeoIp(val code: String) : SiteEntry {
        override val text: String get() = "geoip:$code"
    }

    companion object {
        /** Длина ключевого слова: короче — совпадёт с половиной интернета, длиннее — не имя. */
        val KEYWORD_LENGTH: IntRange = 2..63

        /**
         * Строка → запись; не запись — причина без значения строки целиком
         * (D-22): список вставляют из чужих профилей. `domain:` и `.example.com`
         * — то же, что `example.com`: так их пишут Xray и другие клиенты.
         * `regexp:` не выражается: смысл регулярного выражения у ядер разный (D-05).
         */
        fun parse(raw: String): Outcome<SiteEntry> {
            val line = raw.trim()
            val lower = line.lowercase()
            fun geo(prefix: String, make: (String) -> SiteEntry): Outcome<SiteEntry> {
                val code = lower.removePrefix(prefix).trim()
                return if (RoutingValidator.isValidGeoCode(code)) {
                    Outcome.Success(make(code))
                } else {
                    Outcome.failure(DiagCode.GEO_CODE_INVALID, "неверный код $prefix")
                }
            }
            fun domain(text: String, make: (String) -> SiteEntry): Outcome<SiteEntry> =
                Host.normalizeDomain(text)?.let { Outcome.Success(make(it)) }
                    ?: Outcome.failure(DiagCode.DOMAIN_INVALID, "не домен: ожидается вроде example.com")
            return when {
                lower.startsWith("geosite:") -> geo("geosite:", ::GeoSite)
                lower.startsWith("geoip:") -> geo("geoip:", ::GeoIp)
                lower.startsWith("full:") -> domain(line.substring("full:".length).trim(), ::Full)
                lower.startsWith("domain:") -> domain(line.substring("domain:".length).trim(), ::Domain)
                lower.startsWith("keyword:") -> {
                    val k = lower.removePrefix("keyword:").trim()
                    if (k.length in KEYWORD_LENGTH && k.all { it.isLetterOrDigit() || it == '-' || it == '.' }) {
                        Outcome.Success(Keyword(k))
                    } else {
                        Outcome.failure(DiagCode.DOMAIN_INVALID, "ключевое слово — ${KEYWORD_LENGTH.first}…${KEYWORD_LENGTH.last} букв, цифр, «-» и «.»")
                    }
                }
                lower.startsWith("regexp:") -> Outcome.failure(
                    DiagCode.CAPABILITY_FEATURE_UNSUPPORTED,
                    "регулярные выражения не поддерживаются: смысл у ядер разный (D-05)",
                )
                '/' in line || IpAddress.parse(line) != null -> Cidr.parse(line)?.let { Outcome.Success<SiteEntry>(Address(it.cidr)) }
                    ?: Outcome.failure(DiagCode.CIDR_INVALID, "неверный адрес или подсеть")
                else -> domain(line.removePrefix("*.").removePrefix("."), ::Domain)
            }
        }
    }
}

/** Один свой список — записи в порядке, в каком их ввели, без повторов. */
data class SiteList(val entries: List<SiteEntry> = emptyList()) {
    val isEmpty: Boolean get() = entries.isEmpty()
    val size: Int get() = entries.size

    /** Условие по имени: домены, ключевые слова и geosite — ИЛИ; null — таких записей нет. */
    fun names(): Conditions? {
        val domains = entries.mapNotNull {
            when (it) {
                is SiteEntry.Domain -> DomainMatcher.Suffix(it.name)
                is SiteEntry.Full -> DomainMatcher.Full(it.name)
                is SiteEntry.Keyword -> DomainMatcher.Keyword(it.keyword)
                else -> null
            }
        }
        val sites = entries.filterIsInstance<SiteEntry.GeoSite>().map { it.code }
        return if (domains.isEmpty() && sites.isEmpty()) null else Conditions(domains = domains, geoSites = sites)
    }

    /** Условие по адресу: подсети и geoip — ИЛИ; null — таких записей нет. */
    fun addresses(): Conditions? {
        val cidrs = entries.filterIsInstance<SiteEntry.Address>().map { it.cidr }
        val ips = entries.filterIsInstance<SiteEntry.GeoIp>().map { it.code }
        return if (cidrs.isEmpty() && ips.isEmpty()) null else Conditions(ipCidrs = cidrs, geoIps = ips)
    }

    /** Текст для правки: запись на строку. */
    fun format(): String = entries.joinToString("\n") { it.text }

    companion object {
        /** Предел записей одного списка: с индексом правил (D-89) решение на 1000 записей — микросекунды. */
        const val MAX_ENTRIES: Int = 1000

        /**
         * Текст правки → список. Пустые строки и `#…` пропускаются, повторы —
         * один раз. Неверная строка — ошибка с номером строки, список целиком
         * не принимается: молча выброшенная запись — сайт, который пойдёт не
         * так, как задумано (D-05).
         */
        fun parse(text: String, path: String): Outcome<SiteList> {
            val problems = mutableListOf<Diagnostic>()
            val seen = LinkedHashMap<String, SiteEntry>()
            for ((i, raw) in text.lines().withIndex()) {
                val line = raw.trim()
                if (line.isEmpty() || line.startsWith("#")) continue
                when (val e = SiteEntry.parse(line)) {
                    is Outcome.Failure -> e.errors.forEach { problems += it.copy(message = "строка ${i + 1}: ${it.message}", path = "$path[${i + 1}]") }
                    is Outcome.Success -> seen.putIfAbsent(e.value.text, e.value)
                }
            }
            if (seen.size > MAX_ENTRIES) problems += Diagnostic.error(DiagCode.LIMIT_EXCEEDED, "записей ${seen.size}, предел — $MAX_ENTRIES", path)
            return if (problems.isEmpty()) Outcome.Success(SiteList(seen.values.toList())) else Outcome.Failure(problems)
        }
    }
}

/**
 * Свои списки сайтов (D-93): напрямую, через туннель, блокировать. Одна
 * запись — только в одном списке: иначе её действие зависело бы от порядка,
 * которого пользователь не видит.
 */
data class SiteLists(val direct: SiteList = SiteList(), val proxy: SiteList = SiteList(), val block: SiteList = SiteList()) {
    val isEmpty: Boolean get() = direct.isEmpty && proxy.isEmpty && block.isEmpty

    operator fun get(kind: SiteListKind): SiteList = when (kind) {
        SiteListKind.DIRECT -> direct
        SiteListKind.PROXY -> proxy
        SiteListKind.BLOCK -> block
    }

    fun with(kind: SiteListKind, list: SiteList): SiteLists = when (kind) {
        SiteListKind.DIRECT -> copy(direct = list)
        SiteListKind.PROXY -> copy(proxy = list)
        SiteListKind.BLOCK -> copy(block = list)
    }

    /** Запись в двух списках — ошибка с обоими списками. */
    fun validate(path: String): List<Diagnostic> {
        val where = HashMap<String, SiteListKind>()
        val out = mutableListOf<Diagnostic>()
        for (kind in ORDER) {
            for (e in this[kind].entries) {
                val other = where.putIfAbsent(e.text, kind)
                if (other != null) {
                    val why = "«${e.text}» — и в «${other.wire}», и в «${kind.wire}»: запись — только в одном списке"
                    out += Diagnostic.error(DiagCode.RULE_DUPLICATE, why, "$path.${kind.wire}")
                }
            }
            if (this[kind].size > SiteList.MAX_ENTRIES) {
                out += Diagnostic.error(DiagCode.LIMIT_EXCEEDED, "записей в «${kind.wire}» больше ${SiteList.MAX_ENTRIES}", "$path.${kind.wire}")
            }
        }
        return out
    }

    /**
     * Добавить [other] (импорт): его записи — в его списки; та же запись в
     * другом своём списке — переносится туда, куда её отнёс импорт (последний
     * выбор, и пользователь видел его в сводке).
     */
    fun merge(other: SiteLists): SiteLists {
        val moved = ORDER.flatMap { k -> other[k].entries.map { it.text } }.toSet()
        var out = this
        for (k in ORDER) {
            val kept = this[k].entries.filter { it.text !in moved }
            val added = other[k].entries.filter { e -> kept.none { it.text == e.text } }
            out = out.with(k, SiteList((kept + added).distinctBy { it.text }))
        }
        return out
    }

    companion object {
        val NONE: SiteLists = SiteLists()

        /**
         * Порядок правил: блокировать, через туннель, напрямую. Записи разных
         * списков могут пересекаться (домен в одном, его geosite в другом) —
         * тогда выигрывает более осторожное действие.
         */
        val ORDER: List<SiteListKind> = listOf(SiteListKind.BLOCK, SiteListKind.PROXY, SiteListKind.DIRECT)
    }
}
