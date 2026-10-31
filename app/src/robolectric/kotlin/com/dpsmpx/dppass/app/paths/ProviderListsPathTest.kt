package com.dpsmpx.dppass.app.paths

import com.dpsmpx.dppass.R
import com.dpsmpx.dppass.app.device.expect
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import java.util.Base64

/**
 * Ключевой путь «списки поставщика» (D-94): подписка прислала профиль
 * маршрутизации заголовком `routing` → он хранится, но не действует →
 * карточка ведёт к спискам → включение только после окна с тем, что в них
 * → правила поставщика в активной конфигурации, свои списки — раньше них
 * и выключаются переключателем. Ответ поставщика — синтетический.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [26, 29, 36])
class ProviderListsPathTest {
    @Test
    fun providerListsAreKeptShownAndUsedOnlyAfterConsent() {
        Act().use { act ->
            val c = act.context
            val a = act.launch()
            act.seedSubscription(a, "https://sub.example.com/s/synthetic", LINKS, mapOf("profile-title" to "Synthetic", "routing" to ROUTING))
            fun rules() = act.graph(a).core.activation.state.activeConfig!!.routing.rules.map { it.id.value }
            expect(rules().none { it.startsWith("provider-") }) { "списки поставщика действуют без согласия: ${rules()}" }

            act.tap(a, c.getString(R.string.tab_subscriptions))
            act.waitFor(a, c.getString(R.string.provider_lists_off))
            act.tap(a, c.getString(R.string.provider_lists_off))
            act.waitFor(a, c.getString(R.string.provider_lists_named, "Synthetic routing"))
            expect(act.shows(a, c.getString(R.string.provider_lists_first))) { "нет «сравнивать не с чем»: ${act.texts(a)}" }
            expect(act.shows(a, c.resources.getQuantityString(R.plurals.provider_lists_skipped, 1, 1))) { "DNS профиля не назван невзятым: ${act.texts(a)}" }

            // Окно согласия: закрыли — ничего не включилось.
            act.tap(a, c.getString(R.string.provider_lists_use))
            act.waitFor(a, c.getString(R.string.provider_lists_confirm, 1, 0, 1))
            act.d.back()
            expect(act.graph(a).core.subscriptions.state().valueOrNull()!!.items.single().useProviderLists.not()) { "согласие без нажатия" }

            act.tap(a, c.getString(R.string.provider_lists_use))
            act.waitFor(a, c.getString(R.string.provider_lists_confirm, 1, 0, 1))
            act.tap(a, c.getString(R.string.provider_lists_enable))
            act.d.waitUntil("списки поставщика в конфигурации") { rules() == listOf("provider-block-sites", "provider-direct-sites") }

            // Свои — поверх: та же запись «через туннель» решает раньше «напрямую» поставщика.
            act.d.back()
            act.tap(a, c.getString(R.string.tab_settings))
            act.tap(a, c.getString(R.string.site_lists_title))
            act.tap(a, c.getString(R.string.site_list_proxy))
            act.type(a, c.getString(R.string.site_lists_hint), "example.ru")
            act.tap(a, c.getString(R.string.action_save))
            act.d.waitUntil("свой список раньше списков поставщика") { rules() == listOf("own-proxy-sites", "provider-block-sites", "provider-direct-sites") }
            act.waitFor(a, c.getString(R.string.site_lists_provider, "Synthetic"))
            expect(act.shows(a, c.getString(R.string.site_lists_provider_on))) { "списки поставщика не отмечены включёнными: ${act.texts(a)}" }
            act.tap(a, c.getString(R.string.site_lists_enabled))
            act.d.waitUntil("свои списки выключены") { rules() == listOf("provider-block-sites", "provider-direct-sites") }
            expect(act.graph(a).core.userPolicy.currentOrDefault().lists.proxy.size == 1) { "выключенные свои списки стёрты" }
        }
    }

    private companion object {
        val LINKS: String = Base64.getEncoder().encodeToString(
            listOf(
                "vless://00000000-0000-4000-8000-000000000031@203.0.113.31:443?security=tls&sni=a.example.com#Alpha",
                "trojan://synthetic-password@198.51.100.32:443?sni=b.example.com#Bravo",
            ).joinToString("\n").toByteArray(),
        )
        val ROUTING: String = "happ://routing/onadd/" + Base64.getEncoder().encodeToString(
            """{"Name":"Synthetic routing","RemoteDNSType":"DoH","DirectSites":["example.ru"],"BlockSites":["ads.example.net"]}""".toByteArray(),
        )
    }
}
