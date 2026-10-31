package com.dpsmpx.dppass.routing

import com.dpsmpx.dppass.core.RuleId
import com.dpsmpx.dppass.diagnostics.DiagCode
import com.dpsmpx.dppass.diagnostics.Diagnostic

/**
 * Слои настроек пользователя поверх маршрутизации и DNS (D-93, D-94,
 * D-98): у их правил и серверов DNS — свои начала id. По ним слой снимается
 * и кладётся заново, когда пользователь меняет настройки, а правила
 * поставщика остаются как пришли. Поэтому в маршрутизации поставщика,
 * которую пользователь привязал к подписке (D-98), такие id — ошибка с
 * путём, а не «переименовать молча» (D-05).
 */
object Layers {
    /** Свои списки сайтов (D-93): `own-direct-sites` и подобные; свои серверы DNS слоя. */
    const val OWN: String = "own-"

    /** Списки поставщика из профиля маршрутизации (D-94): `provider-direct-sites` и подобные. */
    const val PROVIDER_LISTS: String = "provider-"

    /** Сервер DNS слоя для имён «через туннель» — копия сервера по умолчанию поставщика (D-98). */
    const val DNS_REMOTE: String = OWN + "remote"

    /** Сервер DNS слоя для имён «напрямую» — системный резолвер мимо туннеля (D-98). */
    const val DNS_LOCAL: String = OWN + "local"

    fun isLayerRule(id: RuleId): Boolean = id.value.startsWith(OWN) || id.value.startsWith(PROVIDER_LISTS)

    fun isLayerServer(id: String): Boolean = id.startsWith(OWN)

    /** Id правил и серверов DNS поставщика, занятые слоями: каждое — ошибка с путём. */
    fun reserved(routing: RoutingPolicy?, dns: DnsPolicy?): List<Diagnostic> {
        val out = mutableListOf<Diagnostic>()
        routing?.rules?.forEachIndexed { i, r ->
            if (isLayerRule(r.id)) out += clash("правило «${r.id.value}»", "$.routing.rules[$i].id")
        }
        dns?.servers?.forEachIndexed { i, s ->
            if (isLayerServer(s.id)) out += clash("сервер DNS «${s.id}»", "$.dns.servers[$i].id")
        }
        return out
    }

    private fun clash(what: String, path: String): Diagnostic = Diagnostic.error(
        DiagCode.ID_DUPLICATE,
        "$what: id с «$OWN» и «$PROVIDER_LISTS» заняты своими настройками DPpass — маршрутизация поставщика не применена",
        path,
    )
}
