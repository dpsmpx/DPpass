package com.dpsmpx.dppass.connection

import com.dpsmpx.dppass.core.ManualClock
import com.dpsmpx.dppass.diagnostics.Outcome
import com.dpsmpx.dppass.engine.mock.MockBackendCompiler
import com.dpsmpx.dppass.engine.mock.MockProxyEngine
import com.dpsmpx.dppass.routing.RouteAction
import com.dpsmpx.dppass.routing.RouteQuery
import com.dpsmpx.dppass.routing.SplitSites
import com.dpsmpx.dppass.storage.InMemoryBlobStore
import com.dpsmpx.dppass.tunnel.PlatformTraits
import kotlinx.coroutines.runBlocking
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertTrue

/** «Проверить маршрут» и список «Напрямую с разбиением» (D-72): список сильнее документа, но не шире туннеля. */
class CoreSplitSitesTest {
    private fun core() =
        DPpassCore(MockBackendCompiler(), MockProxyEngine(), InMemoryBlobStore(), ManualClock(1_000), "com.dpsmpx.dppass", PlatformTraits(true))

    private fun DPpassCore.matches(query: RouteQuery, sites: SplitSites): Boolean =
        assertIs<Outcome.Success<Boolean>>(matchesSplitSites(query, sites)).value

    private val sites = SplitSites.parse("ads.example.com\nexample.net").valueOrNull()!!

    @Test
    fun listedSitesMatchBeforeTheDocument() = runBlocking {
        val core = core()
        val source = File(System.getProperty("dppass.repoRoot"), "tests/data/configs/valid-multi.json").readText()
        assertIs<ActivationResult.Activated>(core.importAndActivate(source).valueOrNull())

        // Документ закрывает ads.example.com, список ведёт его напрямую — и «Проверить маршрут» скажет то же.
        val ads = RouteQuery(domain = "cdn.ads.example.com")
        assertEquals(RouteAction.BLOCK, core.explain(ads)!!.valueOrNull()!!.action)
        assertTrue(core.matches(ads, sites))
        assertTrue(core.matches(RouteQuery(domain = "example.net"), sites))

        // Не из списка, без имени, пустой список — ответ документа, как раньше.
        assertFalse(core.matches(RouteQuery(domain = "example.org"), sites))
        assertFalse(core.matches(RouteQuery(domain = "notexample.net"), sites), "домен с поддоменами, а не хвост строки")
        assertFalse(core.matches(RouteQuery(port = 443), sites))
        assertFalse(core.matches(ads, SplitSites.NONE))

        // Приложение вне туннеля (apps: except) до ядра не доходит — списку решать нечего.
        assertFalse(core.matches(ads.copy(packageName = "com.example.bank"), sites))
        assertTrue(core.matches(ads.copy(packageName = "com.example.browser"), sites))
    }

    @Test
    fun withoutActiveConfigTheListStillAnswers() {
        assertTrue(core().matches(RouteQuery(domain = "www.example.net"), sites))
    }
}
