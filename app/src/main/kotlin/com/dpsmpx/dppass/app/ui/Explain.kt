package com.dpsmpx.dppass.app.ui

import com.dpsmpx.dppass.app.PlanSnapshot
import com.dpsmpx.dppass.connection.ActivationRecord
import com.dpsmpx.dppass.connection.ConnectionPlan
import com.dpsmpx.dppass.connection.Exclusion
import com.dpsmpx.dppass.connection.PolicyBuilder
import com.dpsmpx.dppass.connection.PolicyService
import com.dpsmpx.dppass.core.Host
import com.dpsmpx.dppass.core.IpAddress
import com.dpsmpx.dppass.core.ProfileId
import com.dpsmpx.dppass.core.SubscriptionId
import com.dpsmpx.dppass.diagnostics.DiagCode
import com.dpsmpx.dppass.diagnostics.Diagnostic
import com.dpsmpx.dppass.routing.RouteAction
import com.dpsmpx.dppass.routing.RouteDecision
import com.dpsmpx.dppass.routing.RouteQuery
import com.dpsmpx.dppass.routing.RoutingPolicy
import com.dpsmpx.dppass.tunnel.TunnelSpecBuilder
import java.net.IDN

/*
 * Объяснимость (этап 4, работа 3): почему этот сервер (план D-15 с
 * причинами и исключениями), почему этот маршрут (D-09) и история
 * активаций (D-07). Логика — без Android, проверяется на хосте
 * (`ExplainTest`); экраны только показывают.
 */

/** Попытка плана для экрана: кто, почему на этом месте и чем кончилась. */
data class PlanRow(val profileId: ProfileId, val name: String, val reasons: List<String>, val result: PlanResult)

sealed interface PlanResult {
    data object Connected : PlanResult

    data class Failed(val reason: Diagnostic) : PlanResult

    /** План на следующее подключение: попытки ещё не было. */
    data object Planned : PlanResult
}

/** Исключённый из плана сервер и причина. */
data class PlanExclusion(val name: String, val reason: String)

object PlanView {
    /** Последнее подключение: попытки с исходами. */
    fun attempts(snapshot: PlanSnapshot, name: (ProfileId) -> String): List<PlanRow> = snapshot.attempts.map { a ->
        PlanRow(a.profileId, name(a.profileId), a.reasons, if (a.ok) PlanResult.Connected else PlanResult.Failed(a.failure ?: unknownFailure))
    }

    /** Следующее подключение: план без попыток. */
    fun preview(plan: ConnectionPlan, name: (ProfileId) -> String): List<PlanRow> = plan.attempts.map { a ->
        PlanRow(a.profile.id, name(a.profile.id), a.reasons, PlanResult.Planned)
    }

    fun excluded(list: List<Exclusion>, name: (ProfileId) -> String): List<PlanExclusion> = list.map { PlanExclusion(name(it.profileId), it.reason) }

    private val unknownFailure = Diagnostic.error(DiagCode.INTERNAL_ERROR, "причина отказа не записана")
}

/** Куда пойдёт соединение — для человека. */
enum class RouteVerdict { TUNNEL, DIRECT, BLOCKED }

/** Почему (D-09): правило политики, правило своего документа или поведение по умолчанию. */
sealed interface RouteWhy {
    /** «Блокировать рекламу» (D-38). */
    data object Ads : RouteWhy

    /** «Российское напрямую»: сайт из `geosite:category-ru`. */
    data object RuSites : RouteWhy

    /** «Российское напрямую»: адрес из `geoip:ru`. */
    data object RuIp : RouteWhy

    /** Режим «авто» (D-45): отечественное напрямую после всех правил. */
    data object AutoDomestic : RouteWhy

    /** Приложение вне туннеля по выбору приложений. */
    data object AppOutside : RouteWhy

    /** Локальная сеть мимо туннеля: её маршруты TUN не берёт («Локальные сети мимо VPN»). */
    data object LocalNetwork : RouteWhy

    /** Ни одно правило не сработало — действие по умолчанию. */
    data object Default : RouteWhy

    /** Правило своего документа (D-09: называется по id). */
    data class DocumentRule(val id: String) : RouteWhy
}

data class RouteAnswer(val verdict: RouteVerdict, val why: RouteWhy)

object RouteExplain {
    /**
     * Ввод «Почему этот маршрут» → запрос: имя сайта, адрес IP или ссылка
     * (берётся её хост). Пусто — только приложение [packageName]; null —
     * ни имени, ни адреса.
     */
    fun query(text: String, packageName: String?): RouteQuery? {
        val raw = text.trim()
        if (raw.isEmpty()) return packageName?.let { RouteQuery(packageName = it) }
        var host = raw.substringAfter("://").substringBefore('/').substringBefore('?').substringBefore('#').substringAfterLast('@')
        host = when {
            host.startsWith("[") -> host.removePrefix("[").substringBefore("]")
            host.count { it == ':' } == 1 -> host.substringBefore(':')
            else -> host
        }
        IpAddress.parse(host)?.let { return RouteQuery(ip = it, packageName = packageName) }
        // Имя не латиницей («пример.рф») — в форме ASCII, как его ищут правила и geosite.
        val ascii = runCatching { IDN.toASCII(host, IDN.ALLOW_UNASSIGNED) }.getOrNull() ?: return null
        val domain = Host.normalizeDomain(ascii) ?: return null
        return RouteQuery(domain = domain, packageName = packageName)
    }

    /**
     * Локальный адрес при «Локальные сети мимо VPN»: TUN его маршрутов не
     * берёт ([TunnelSpecBuilder.LAN]), до правил ядра соединение не доходит.
     */
    fun localBypass(query: RouteQuery, policy: RoutingPolicy): RouteAnswer? {
        val ip = query.ip ?: return null
        if (!policy.bypassLan || TunnelSpecBuilder.LAN.none { ip in it }) return null
        return RouteAnswer(RouteVerdict.DIRECT, RouteWhy.LocalNetwork)
    }

    /** Решение ядра → ответ: правила политики — по их постоянным id (D-38). */
    fun answer(decision: RouteDecision, query: RouteQuery, policy: RoutingPolicy): RouteAnswer {
        val verdict = when (decision.action) {
            RouteAction.PROXY -> RouteVerdict.TUNNEL
            RouteAction.DIRECT -> RouteVerdict.DIRECT
            RouteAction.BLOCK -> RouteVerdict.BLOCKED
        }
        val why = when (val id = decision.ruleId?.value) {
            PolicyBuilder.RULE_ADS -> RouteWhy.Ads
            PolicyBuilder.RULE_RU_SITES -> RouteWhy.RuSites
            PolicyBuilder.RULE_RU_IP -> RouteWhy.RuIp
            null -> when {
                query.packageName?.let { !policy.apps.includes(it) } == true -> RouteWhy.AppOutside
                policy.automaticDomestic && decision.action == RouteAction.DIRECT && policy.defaultAction != RouteAction.DIRECT -> RouteWhy.AutoDomestic
                else -> RouteWhy.Default
            }
            else -> RouteWhy.DocumentRule(id)
        }
        return RouteAnswer(verdict, why)
    }
}

/** Откуда пришла конфигурация записи истории (`ActivationRecord.source`). */
sealed interface HistorySource {
    data object Own : HistorySource

    data class Subscription(val id: SubscriptionId, val revision: Long?) : HistorySource

    /** Откат (D-07) с версии [fromRevision] на предыдущую. */
    data class Rollback(val fromRevision: Long?) : HistorySource

    /** Источник, которого этот выпуск не знает: показать как есть, а не «ближайшее похожее» (D-05). */
    data class Other(val raw: String) : HistorySource
}

/** История активаций для экрана (D-07): новые сверху. */
object ActivationHistory {
    fun rows(history: List<ActivationRecord>): List<ActivationRecord> = history.sortedByDescending { it.revision }

    /** `user-import`, `subscription:<id>#<ревизия>` или `rollback:<версия>`. */
    fun source(raw: String): HistorySource = when {
        raw == PolicyService.OWN_DOCUMENT -> HistorySource.Own
        raw.startsWith(SUBSCRIPTION) -> raw.removePrefix(SUBSCRIPTION).let {
            HistorySource.Subscription(SubscriptionId(it.substringBefore('#')), it.substringAfter('#', "").toLongOrNull())
        }
        raw.startsWith(ROLLBACK) -> HistorySource.Rollback(raw.removePrefix(ROLLBACK).toLongOrNull())
        else -> HistorySource.Other(raw)
    }

    /** Начало контрольной суммы: отличить одну присланную конфигурацию от другой глазами. */
    fun shortChecksum(checksum: String): String = checksum.substringAfter(':').take(12)

    private const val SUBSCRIPTION = "subscription:"
    private const val ROLLBACK = "rollback:"
}
