package com.dpsmpx.dppass.app.paths

import com.dpsmpx.dppass.R
import com.dpsmpx.dppass.app.device.expect
import com.dpsmpx.dppass.app.ui.Formats
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import java.util.Base64

/**
 * Ключевой путь «карточка подписки» (D-90): что прислал поставщик —
 * название, трафик, срок (скоро — предупреждением), пропущенные записи — на
 * карточке; из её меню — переименовать и удалить с подтверждением. Ответ
 * поставщика — синтетический (адреса TEST-NET, домены example.com).
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [36])
class SubscriptionCardPathTest {
    @Test
    fun cardShowsWhatProviderSentAndMenuEditsIt() {
        Act().use { act ->
            val c = act.context
            val a = act.launch()
            val expire = System.currentTimeMillis() / 1000 + 2 * DAY_SECONDS + 2 * 3600
            act.seedSubscription(
                a,
                "https://sub.example.com/s/synthetic",
                Base64.getEncoder().encodeToString(LINKS.toByteArray()),
                mapOf(
                    "profile-title" to "Synthetic provider",
                    "subscription-userinfo" to "upload=$GIB; download=${2 * GIB}; total=${10 * GIB}; expire=$expire",
                    "profile-update-interval" to "6",
                ),
            )
            act.tap(a, c.getString(R.string.tab_subscriptions))
            act.waitFor(a, "Synthetic provider")

            val units = c.resources.getStringArray(R.array.units_bytes).toList()
            val locale = c.resources.configuration.locales[0]
            val traffic = c.getString(R.string.subs_traffic, Formats.bytes(3 * GIB, units, locale), Formats.bytes(10 * GIB, units, locale))
            expect(act.shows(a, traffic)) { "нет «$traffic»: ${act.texts(a)}" }
            val left = c.resources.getQuantityString(R.plurals.days, 2, 2)
            expect(act.shows(a, left)) { "нет срока «$left»: ${act.texts(a)}" }
            expect(act.colorOf(a, left) == c.getColor(R.color.warning)) { "срок через 2 дня — не предупреждением" }
            expect(act.shows(a, c.getString(R.string.subs_active))) { "подписка не отмечена применённой: ${act.texts(a)}" }
            expect(act.shows(a, c.resources.getQuantityString(R.plurals.subs_skipped, 1, 1))) { "нет «пропущено 1»: ${act.texts(a)}" }
            expect(act.shows(a, c.getString(R.string.subs_auto_every, 12))) { "нет интервала автообновления: ${act.texts(a)}" }

            act.tap(a, c.getString(R.string.subs_menu, "Synthetic provider"))
            act.tap(a, c.getString(R.string.subs_rename))
            act.type(a, c.getString(R.string.subs_name_hint), "Renamed")
            act.tap(a, c.getString(R.string.action_save))
            act.waitFor(a, "Renamed")
            expect(!act.shows(a, "Synthetic provider")) { "после переименования — прежнее имя: ${act.texts(a)}" }

            act.tap(a, c.getString(R.string.subs_menu, "Renamed"))
            act.tap(a, c.getString(R.string.subs_remove))
            act.waitFor(a, c.getString(R.string.subs_remove_confirm, "Renamed"))
            act.tap(a, c.getString(android.R.string.ok))
            act.waitFor(a, c.getString(R.string.subs_empty))
        }
    }

    private companion object {
        const val GIB = 1L shl 30
        const val DAY_SECONDS = 24 * 3600L
        val LINKS = listOf(
            "vless://00000000-0000-4000-8000-000000000031@203.0.113.31:443?security=tls&sni=a.example.com#Alpha",
            "trojan://synthetic-password@198.51.100.32:443?sni=b.example.com#Bravo",
            "tuic://00000000-0000-4000-8000-000000000033@203.0.113.33:443#Charlie",
        ).joinToString("\n")
    }
}
