package com.dpsmpx.dppass.app.ui

import com.dpsmpx.dppass.app.PlanSnapshot
import com.dpsmpx.dppass.config.ProtocolSpec
import com.dpsmpx.dppass.config.SecuritySpec
import com.dpsmpx.dppass.config.ServerProfile
import com.dpsmpx.dppass.config.TransportSpec
import com.dpsmpx.dppass.connection.ActivationRecord
import com.dpsmpx.dppass.connection.ActivationStatus
import com.dpsmpx.dppass.connection.ActivationStep
import com.dpsmpx.dppass.connection.AppMode
import com.dpsmpx.dppass.connection.AttemptRecord
import com.dpsmpx.dppass.connection.ConnectionPlan
import com.dpsmpx.dppass.connection.Exclusion
import com.dpsmpx.dppass.connection.PlannedAttempt
import com.dpsmpx.dppass.connection.PolicyBuilder
import com.dpsmpx.dppass.connection.RoutingMode
import com.dpsmpx.dppass.connection.ServerlessMode
import com.dpsmpx.dppass.connection.ServerlessSettings
import com.dpsmpx.dppass.connection.UserPolicy
import com.dpsmpx.dppass.core.Endpoint
import com.dpsmpx.dppass.core.Host
import com.dpsmpx.dppass.core.IpAddress
import com.dpsmpx.dppass.core.ProfileId
import com.dpsmpx.dppass.core.RuleId
import com.dpsmpx.dppass.core.SubscriptionId
import com.dpsmpx.dppass.diagnostics.DiagCode
import com.dpsmpx.dppass.diagnostics.Diagnostic
import com.dpsmpx.dppass.diagnostics.Secret
import com.dpsmpx.dppass.routing.GeoResolver
import com.dpsmpx.dppass.routing.RouteAction
import com.dpsmpx.dppass.routing.RouteDecision
import com.dpsmpx.dppass.routing.RouteEvaluator
import com.dpsmpx.dppass.routing.RouteQuery
import com.dpsmpx.dppass.routing.RoutingPolicy
import com.dpsmpx.dppass.routing.SiteEntry
import com.dpsmpx.dppass.routing.SiteList
import com.dpsmpx.dppass.routing.SiteListKind
import com.dpsmpx.dppass.routing.SiteLists
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNull

/** Объяснимость (этап 4): что экраны «почему» покажут — без Android. */
class ExplainTest {
    // Синтетические имена и адреса: example.*, TEST-NET (RFC 5737), документационный IPv6 (RFC 3849).
    private val geo = object : GeoResolver {
        override fun siteMatches(code: String, domain: String): Boolean = when (code) {
            PolicyBuilder.GEOSITE_RU -> domain.endsWith(".example.ru")
            PolicyBuilder.GEOSITE_ADS -> domain.startsWith("ads.")
            else -> false
        }

        override fun ipMatches(code: String, ip: IpAddress): Boolean = code == PolicyBuilder.GEOIP_RU && ip == IpAddress.parse("198.51.100.7")
    }

    private fun answer(policy: UserPolicy, query: RouteQuery): RouteAnswer {
        val routing = PolicyBuilder.routing(policy)
        return RouteExplain.answer(RouteEvaluator(routing, geo).decide(query), query, routing)
    }

    @Test
    fun inputBecomesQuery() {
        assertEquals(RouteQuery(domain = "www.example.com"), RouteExplain.query("  https://User@WWW.Example.COM:8443/путь?q=1#x ", null))
        assertEquals(RouteQuery(domain = "host.example.net", packageName = "org.example.app"), RouteExplain.query("host.example.net.", "org.example.app"))
        assertEquals(RouteQuery(ip = IpAddress.parse("192.0.2.1")), RouteExplain.query("192.0.2.1:80", null))
        assertEquals(RouteQuery(ip = IpAddress.parse("2001:db8::1")), RouteExplain.query("[2001:db8::1]:443", null))
        assertEquals(RouteQuery(ip = IpAddress.parse("2001:db8::1")), RouteExplain.query("2001:db8::1", null))
        // Имя не латиницей — в форме ASCII, как в правилах и geosite.
        assertEquals(RouteQuery(domain = "xn--e1afmkfd.xn--p1ai"), RouteExplain.query("пример.рф", null))
        // Пусто — только приложение; ни приложения, ни имени — нечего проверять.
        assertEquals(RouteQuery(packageName = "org.example.app"), RouteExplain.query(" ", "org.example.app"))
        assertNull(RouteExplain.query("", null))
        assertNull(RouteExplain.query("не сайт!", null))
        assertNull(RouteExplain.query("https://", null))
    }

    @Test
    fun policyRulesAreNamedByTheirIds() {
        val ru = UserPolicy(mode = RoutingMode.RU_DIRECT, blockAds = true)
        assertEquals(RouteAnswer(RouteVerdict.BLOCKED, RouteWhy.Ads), answer(ru, RouteQuery(domain = "ads.example.com")))
        assertEquals(RouteAnswer(RouteVerdict.DIRECT, RouteWhy.RuSites), answer(ru, RouteQuery(domain = "shop.example.ru")))
        assertEquals(RouteAnswer(RouteVerdict.DIRECT, RouteWhy.RuIp), answer(ru, RouteQuery(ip = IpAddress.parse("198.51.100.7"))))
        assertEquals(RouteAnswer(RouteVerdict.TUNNEL, RouteWhy.Default), answer(ru, RouteQuery(domain = "www.example.com")))
    }

    @Test
    fun ownListOverProviderListIsNamed() {
        // D-94: своя запись — раньше списка поставщика, а его запись — раньше режима.
        fun entries(vararg s: String) = SiteList(s.map { SiteEntry.parse(it).valueOrNull()!! })
        val policy = UserPolicy(mode = RoutingMode.RU_DIRECT, lists = SiteLists(proxy = entries("shop.example.ru")))
        val routing = PolicyBuilder.routing(policy, SiteLists(direct = entries("example.ru", "example.com")))
        fun why(domain: String) = RouteQuery(domain = domain).let { q -> RouteExplain.answer(RouteEvaluator(routing, geo).decide(q), q, routing) }
        assertEquals(RouteAnswer(RouteVerdict.TUNNEL, RouteWhy.OwnList(SiteListKind.PROXY)), why("shop.example.ru"))
        assertEquals(RouteAnswer(RouteVerdict.DIRECT, RouteWhy.ProviderList(SiteListKind.DIRECT)), why("news.example.ru"))
        assertEquals(RouteAnswer(RouteVerdict.DIRECT, RouteWhy.ProviderList(SiteListKind.DIRECT)), why("www.example.com"))
    }

    @Test
    fun noRuleMeansAppSplitAutoOrDefault() {
        // Приложение вне туннеля — напрямую раньше всех правил.
        val except = UserPolicy(appMode = AppMode.EXCEPT, apps = setOf("org.example.bank"))
        assertEquals(
            RouteAnswer(RouteVerdict.DIRECT, RouteWhy.AppOutside),
            answer(except, RouteQuery(domain = "www.example.com", packageName = "org.example.bank")),
        )
        assertEquals(
            RouteAnswer(RouteVerdict.TUNNEL, RouteWhy.Default),
            answer(except, RouteQuery(domain = "www.example.com", packageName = "org.example.other")),
        )
        // «Авто» (D-45): отечественное напрямую после всех правил.
        val auto = UserPolicy(mode = RoutingMode.AUTO)
        assertEquals(RouteAnswer(RouteVerdict.DIRECT, RouteWhy.AutoDomestic), answer(auto, RouteQuery(domain = "shop.example.ru")))
        assertEquals(RouteAnswer(RouteVerdict.TUNNEL, RouteWhy.Default), answer(auto, RouteQuery(domain = "www.example.com")))
    }

    @Test
    fun documentRuleKeepsItsId() {
        val routing = RoutingPolicy(defaultAction = RouteAction.DIRECT)
        val query = RouteQuery(domain = "www.example.com")
        assertEquals(
            RouteAnswer(RouteVerdict.TUNNEL, RouteWhy.DocumentRule("work")),
            RouteExplain.answer(RouteDecision(RouteAction.PROXY, RuleId("work"), "правило work"), query, routing),
        )
        // Документ с действием по умолчанию DIRECT и без автосплита — это действие по умолчанию, а не «авто».
        assertEquals(RouteAnswer(RouteVerdict.DIRECT, RouteWhy.Default), RouteExplain.answer(RouteDecision(RouteAction.DIRECT, null, ""), query, routing))
    }

    @Test
    fun providerRoutingRuleIsTheProviders() {
        // Маршрутизация поставщика (D-98): его правило — его, даже с id как у правила политики; свой список — свой.
        val routing = RoutingPolicy()
        val query = RouteQuery(domain = "ads.example.com")
        fun why(id: String) = RouteExplain.answer(RouteDecision(RouteAction.BLOCK, RuleId(id), ""), query, routing, provider = "Дом").why
        assertEquals(RouteWhy.ProviderRule("p-ads", "Дом"), why("p-ads"))
        assertEquals(RouteWhy.ProviderRule(PolicyBuilder.RULE_ADS, "Дом"), why(PolicyBuilder.RULE_ADS))
        assertEquals(RouteWhy.OwnList(SiteListKind.BLOCK), why(PolicyBuilder.ownRule(SiteListKind.BLOCK, true)))
        assertEquals(RouteWhy.Ads, RouteExplain.answer(RouteDecision(RouteAction.BLOCK, RuleId(PolicyBuilder.RULE_ADS), ""), query, routing).why)
    }

    @Test
    fun localNetworksBypassTheTunnelOnlyWhenAsked() {
        val on = PolicyBuilder.routing(UserPolicy(bypassLan = true))
        val off = PolicyBuilder.routing(UserPolicy(bypassLan = false))
        for (local in listOf("192.168.1.10", "10.1.2.3", "172.16.0.1", "169.254.1.1", "100.64.0.1", "fd00::1", "fe80::1")) {
            val q = RouteQuery(ip = IpAddress.parse(local))
            assertEquals(RouteAnswer(RouteVerdict.DIRECT, RouteWhy.LocalNetwork), RouteExplain.localBypass(q, on), local)
            assertNull(RouteExplain.localBypass(q, off), local)
        }
        assertNull(RouteExplain.localBypass(RouteQuery(ip = IpAddress.parse("203.0.113.5")), on))
        assertNull(RouteExplain.localBypass(RouteQuery(domain = "router.example.lan"), on))
    }

    private fun profile(id: String) =
        ServerProfile(
            ProfileId(id),
            "🇳🇱 Сервер $id",
            Endpoint(Host.Domain("$id.example.net"), 443),
            ProtocolSpec.Trojan(Secret("synthetic")),
            TransportSpec.Tcp,
            SecuritySpec.Tls("$id.example.net", emptyList(), null),
        )

    @Test
    fun planRowsKeepOrderReasonsAndOutcomes() {
        val refused = Diagnostic.error(DiagCode.ENDPOINT_UNREACHABLE, "сервер недоступен из этой сети")
        val snapshot = PlanSnapshot(
            atMillis = 1_000,
            attempts = listOf(
                AttemptRecord(ProfileId("a"), listOf("выбран пользователем"), ok = false, failure = refused),
                AttemptRecord(ProfileId("b"), listOf("последний удачный кандидат"), ok = false, failure = null),
                AttemptRecord(ProfileId("c"), listOf("был здоров"), ok = true, failure = null),
            ),
            excluded = listOf(Exclusion(ProfileId("d"), "за пределом 3 попыток на подключение")),
            viaRelay = false,
        )
        val names = { id: ProfileId -> "Сервер ${id.value}" }
        val rows = PlanView.attempts(snapshot, names)
        assertEquals(listOf("a", "b", "c"), rows.map { it.profileId.value })
        assertEquals(PlanResult.Failed(refused), rows[0].result)
        // Отказ без записанной причины — так и сказано, а не «подключён».
        assertEquals(DiagCode.INTERNAL_ERROR, assertIs<PlanResult.Failed>(rows[1].result).reason.code)
        assertEquals(PlanResult.Connected, rows[2].result)
        assertEquals(listOf("был здоров"), rows[2].reasons)
        assertEquals(listOf(PlanExclusion("Сервер d", "за пределом 3 попыток на подключение")), PlanView.excluded(snapshot.excluded, names))

        val plan = ConnectionPlan(listOf(PlannedAttempt(profile("x"), listOf("ещё не проверялся"))), emptyList(), null, null)
        assertEquals(listOf(PlanRow(ProfileId("x"), "Сервер x", listOf("ещё не проверялся"), PlanResult.Planned)), PlanView.preview(plan, names))
    }

    private fun record(revision: Long, source: String, status: ActivationStatus) =
        ActivationRecord(revision, revision * 1000, source, "0123456789abcdef0123", null, null, status, null, null)

    @Test
    fun historyIsNewestFirstWithReadableSources() {
        val history = listOf(
            record(1, "user-import", ActivationStatus.SUPERSEDED),
            record(3, "rollback:2", ActivationStatus.ACTIVE),
            record(2, "subscription:sub-1#7", ActivationStatus.ROLLED_BACK),
            record(4, "subscription:sub-1#8", ActivationStatus.REJECTED)
                .copy(failedStep = ActivationStep.COMPILE, failure = "ROUTE_COMPILATION_FAILED: правило не выражается"),
        )
        assertEquals(listOf(4L, 3L, 2L, 1L), ActivationHistory.rows(history).map { it.revision })
        assertEquals(HistorySource.Own, ActivationHistory.source("user-import"))
        assertEquals(HistorySource.Subscription(SubscriptionId("sub-1"), 7), ActivationHistory.source("subscription:sub-1#7"))
        assertEquals(HistorySource.Subscription(SubscriptionId("sub-1"), null), ActivationHistory.source("subscription:sub-1"))
        assertEquals(HistorySource.Rollback(2), ActivationHistory.source("rollback:2"))
        // Незнакомый источник — как есть, а не «своя конфигурация» (D-05).
        assertEquals(HistorySource.Other("future:x"), ActivationHistory.source("future:x"))
        assertEquals("0123456789ab", ActivationHistory.shortChecksum("0123456789abcdef0123"))
    }

    @Test
    fun serverlessAnswersAreAlwaysDirectWithTheReason() {
        // D-73: сервера нет — всё напрямую; вопрос только, с разбиением ли и почему.
        val policy = ServerlessMode.config(
            ServerlessSettings(apps = ServerlessSettings.Apps.OWN, ownMode = AppMode.EXCEPT, ownApps = setOf("com.example.bank")),
            UserPolicy.DEFAULT,
        ).routing
        val site = RouteQuery(domain = "video.example.com")
        assertEquals(RouteAnswer(RouteVerdict.DIRECT, RouteWhy.SplitSites), RouteExplain.serverless(site, policy, inList = true, splitRest = false))
        assertEquals(RouteAnswer(RouteVerdict.DIRECT, RouteWhy.ServerlessDirect), RouteExplain.serverless(site, policy, inList = false, splitRest = false))
        assertEquals(RouteAnswer(RouteVerdict.DIRECT, RouteWhy.ServerlessSplit), RouteExplain.serverless(site, policy, inList = false, splitRest = true))
        // Приложение вне туннеля режима и локальная сеть — их ядро не видит вовсе.
        assertEquals(RouteWhy.AppOutside, RouteExplain.serverless(site.copy(packageName = "com.example.bank"), policy, inList = true, splitRest = true).why)
        val lan = RouteQuery(ip = IpAddress.parse("192.168.1.1"))
        assertEquals(RouteWhy.LocalNetwork, RouteExplain.serverless(lan, policy, inList = false, splitRest = true).why)
    }
}
