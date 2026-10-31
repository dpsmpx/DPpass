package com.dpsmpx.dppass.app.paths

import android.widget.LinearLayout
import com.dpsmpx.dppass.R
import com.dpsmpx.dppass.app.device.expect
import com.dpsmpx.dppass.app.ui.Host
import com.dpsmpx.dppass.diagnostics.Outcome
import com.dpsmpx.dppass.subscriptions.FetchedPayload
import com.dpsmpx.dppass.subscriptions.RoutingBinding
import com.dpsmpx.dppass.subscriptions.SubscriptionFetcher
import kotlinx.coroutines.runBlocking
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import java.util.Base64

/**
 * Ключевой путь «маршрутизация поставщика» (D-98): подписка — документ
 * DPpass → его правила не действуют без согласия → карточка ведёт к окну,
 * где сказано, что они заменят и что останется своим → закрыли — ничего;
 * включили у не применённой подписки — записано, «подействует, когда
 * применят» → применили — правила поставщика, в настройках — пометка →
 * выключили из окна — снова свои. Сети нет: ответы поставщика даёт тест, а
 * включение у применённой (загрузка заново) — `ProviderPolicyTest` на хосте.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [26, 29, 36])
class ProviderPolicyPathTest {
    @Test
    fun providerRoutingIsOfferedTakenOnlyAfterConsentAndComesBack() {
        Act().use { act ->
            val c = act.context
            val a = act.launch()
            act.seedSubscription(a, DOC_URL, DOC, mapOf("profile-title" to "Document"))
            fun core() = act.graph(a).core
            fun rules() = core().activation.state.activeConfig!!.routing.rules.map { it.id.value }
            fun doc() = core().subscriptions.state().valueOrNull()!!.items.single { it.displayName == "Document" }
            expect("p-ads" !in rules()) { "маршрутизация поставщика действует без согласия: ${rules()}" }
            // Применена другая подписка: включение у документа — без загрузки.
            act.seedSubscription(a, "https://sub.example.org/s/links", LINKS, mapOf("profile-title" to "Links"))

            act.tap(a, c.getString(R.string.tab_subscriptions))
            act.waitFor(a, c.getString(R.string.provider_policy_off))
            act.tap(a, c.getString(R.string.provider_policy_off))
            act.waitFor(a, c.getString(R.string.provider_policy_confirm, "Document"))
            act.d.back()
            expect(doc().binding == RoutingBinding.USER_ROUTING) { "привязка без нажатия" }

            act.tap(a, c.getString(R.string.provider_policy_off))
            act.waitFor(a, c.getString(R.string.provider_policy_confirm, "Document"))
            act.tap(a, c.getString(R.string.provider_policy_enable))
            act.d.waitUntil("привязка записана") { doc().binding == RoutingBinding.PROVIDER_ROUTING }
            act.waitFor(a, c.getString(R.string.provider_policy_on))
            act.tap(a, c.getString(R.string.provider_policy_on))
            act.waitFor(a, c.getString(R.string.provider_policy_state_not_applied))
            act.d.back()

            // Применили документ — действуют правила поставщика, настройки маршрутизации говорят об этом.
            val provider = SubscriptionFetcher { _, _ ->
                Outcome.Success(FetchedPayload(DOC.toByteArray(), mapOf("profile-title" to "Document"), System.currentTimeMillis()))
            }
            val run = runBlocking { core().subscriptions.refresh(doc().id, provider, act.graph(a).appVersion) }
            expect(run.valueOrNull()?.applied == true) { "документ не применён: $run" }
            expect(rules() == listOf("p-ads")) { "нет правил поставщика: ${rules()}" }
            act.d.main { (a as Host).changed() }
            act.tap(a, c.getString(R.string.tab_settings))
            act.waitFor(a, c.getString(R.string.routing_provider_note, "Document"))

            // Выключили из окна у подписки — снова свои маршрутизация и DNS. В настройках та же подпись — у раздела.
            act.tap(a, c.getString(R.string.tab_subscriptions), LinearLayout::class.java)
            act.tap(a, c.getString(R.string.provider_policy_on))
            act.waitFor(a, c.getString(R.string.provider_policy_state_on))
            act.tap(a, c.getString(R.string.provider_policy_disable))
            act.d.waitUntil("снова своя маршрутизация") { "p-ads" !in rules() && doc().binding == RoutingBinding.USER_ROUTING }
            expect(core().providerPolicyInEffect() == null) { "маршрутизация поставщика осталась действовать" }
        }
    }

    private companion object {
        const val DOC_URL = "https://sub.example.com/s/document"

        /** Документ DPpass поставщика — синтетический (TEST-NET, example). */
        val DOC: String = """
            {"format":"dppass.config","format_version":2,
             "profiles":[{"id":"t1","name":"Tango","server":"203.0.113.41","port":443,
               "protocol":{"type":"trojan","password":"synthetic-password-41"},
               "security":{"type":"tls","server_name":"t1.example.com"}}],
             "routing":{"rules":[{"id":"p-ads","action":"block","domain_suffix":["ads.example.com"]}]},
             "dns":{"servers":[{"id":"p-doh","type":"https","url":"https://dns.example.net/dns-query","route":"tunnel"}],"default":"p-doh"}}
        """.trimIndent()

        val LINKS: String = Base64.getEncoder().encodeToString(
            "trojan://synthetic-password@198.51.100.32:443?sni=b.example.com#Bravo".toByteArray(),
        )
    }
}
