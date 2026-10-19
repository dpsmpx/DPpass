package com.dpsmpx.dppass.routing

import com.dpsmpx.dppass.core.Host
import com.dpsmpx.dppass.diagnostics.DiagCode
import com.dpsmpx.dppass.diagnostics.Diagnostic
import com.dpsmpx.dppass.diagnostics.Outcome

/**
 * Сайты «напрямую с разбиением» (D-72): выбор пользователя на этом
 * телефоне, а не часть документа (D-06, D-11). TCP к ним идёт прямо, с
 * разбиением начала TLS (как D-68), UDP 443 (QUIC) — закрыт.
 *
 * [domains] — домены с поддоменами в нормальной форме; [geoSites] — списки
 * geosite набора геоданных, с атрибутами `@…`, как в документе (D-27).
 */
data class SplitSites(val domains: List<String> = emptyList(), val geoSites: List<String> = emptyList()) {
    val isEmpty: Boolean get() = domains.isEmpty() && geoSites.isEmpty()

    val size: Int get() = domains.size + geoSites.size

    /** Условие маршрутизации: имя совпало с доменом списка ИЛИ входит в список geosite. */
    fun conditions(): Conditions = Conditions(domains = domains.map { DomainMatcher.Suffix(it) }, geoSites = geoSites)

    /** Обратно в текст настройки: запись на строку, сначала домены. */
    fun format(): String = (domains + geoSites.map { GEOSITE + it }).joinToString("\n")

    companion object {
        val NONE: SplitSites = SplitSites()

        /** Предел записей: список — для выбранных сайтов, а не замена маршрутизации. */
        const val MAX_ENTRIES: Int = 200

        /** Путь находок: настройка телефона, а не поле документа (D-05). */
        const val PATH: String = "settings.split_sites"

        private const val GEOSITE = "geosite:"

        /**
         * Текст настройки → список. Пустые строки и строки с `#` в начале —
         * пропускаются; повторы — один раз. Неверная запись — ошибка с
         * номером строки (с 1), список целиком не принимается: молча
         * выброшенная запись — сайт, который пойдёт не так, как задумано (D-05).
         */
        fun parse(text: String): Outcome<SplitSites> {
            val problems = mutableListOf<Diagnostic>()
            val domains = LinkedHashSet<String>()
            val sites = LinkedHashSet<String>()
            for ((i, raw) in text.lines().withIndex()) {
                val line = raw.trim()
                if (line.isEmpty() || line.startsWith("#")) continue
                val at = "$PATH[${i + 1}]"
                if (line.lowercase().startsWith(GEOSITE)) {
                    val code = line.substring(GEOSITE.length).trim().lowercase()
                    if (RoutingValidator.isValidGeoCode(code)) {
                        sites += code
                    } else {
                        problems += Diagnostic.error(DiagCode.GEO_CODE_INVALID, "строка ${i + 1}: неверный список geosite «$line»", at)
                    }
                    continue
                }
                val domain = Host.normalizeDomain(line.removePrefix("*.").removePrefix("."))
                if (domain == null) {
                    problems += Diagnostic.error(
                        DiagCode.DOMAIN_INVALID,
                        "строка ${i + 1}: «$line» — не домен (example.com) и не список geosite (geosite:имя)",
                        at,
                    )
                } else {
                    domains += domain
                }
            }
            if (domains.size + sites.size > MAX_ENTRIES) {
                problems += Diagnostic.error(
                    DiagCode.LIMIT_EXCEEDED,
                    "записей ${domains.size + sites.size}, предел — $MAX_ENTRIES",
                    PATH,
                )
            }
            return if (problems.isEmpty()) Outcome.Success(SplitSites(domains.toList(), sites.toList())) else Outcome.Failure(problems)
        }
    }
}
