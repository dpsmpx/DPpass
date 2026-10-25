package com.dpsmpx.dppass.app.paths

import com.dpsmpx.dppass.R
import com.dpsmpx.dppass.app.device.expect
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

/**
 * Ключевой путь «импорт» (D-90): ссылки из буфера обмена → сводка, что
 * годится и почему нет → «Добавить и применить» → карточка своих серверов
 * и серверы в списке. Данные — синтетические (адреса TEST-NET, RFC 5737).
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [36])
class ImportPathTest {
    @Test
    fun linksFromClipboardBecomeServers() {
        Act().use { act ->
            val c = act.context
            val a = act.launch()
            act.clipboard(LINKS)
            act.tap(a, c.getString(R.string.tab_subscriptions))
            act.tap(a, c.getString(R.string.add_title))
            act.tap(a, c.getString(R.string.import_clipboard))

            // Сводка: сколько годится, почему нет — до нажатия ничего не применено (T13).
            act.waitFor(a, c.resources.getQuantityString(R.plurals.import_links_summary, 3, 2, 3))
            expect(act.shows(a, "tuic://")) { "в сводке нет причины пропуска: ${act.texts(a)}" }
            expect(act.graph(a).core.activation.state.activeConfig == null) { "конфигурация применена до нажатия" }
            act.type(a, c.getString(R.string.subs_name_hint), "Synthetic")
            act.tap(a, c.getString(R.string.import_links_add))

            act.waitFor(a, c.resources.getQuantityString(R.plurals.servers_count, 2, 2))
            expect(act.shows(a, "Synthetic")) { "нет карточки «Synthetic»: ${act.texts(a)}" }
            expect(act.shows(a, c.getString(R.string.subs_active))) { "свои серверы не применены: ${act.texts(a)}" }
            expect(act.shows(a, c.resources.getQuantityString(R.plurals.subs_skipped, 1, 1))) { "нет «пропущено 1»: ${act.texts(a)}" }
            act.tap(a, c.resources.getQuantityString(R.plurals.subs_skipped, 1, 1))
            act.waitFor(a, c.getString(R.string.subs_skipped_title, "Synthetic"))
            expect(act.shows(a, c.getString(R.string.subs_skipped_entry, 3))) { "пропущенная запись — не третья: ${act.texts(a)}" }
            act.d.back()

            act.tap(a, c.getString(R.string.tab_servers))
            act.waitFor(a, "Alpha")
            expect(act.shows(a, "Bravo")) { "в «Серверах» нет второго сервера: ${act.texts(a)}" }
        }
    }

    private companion object {
        val LINKS = listOf(
            "vless://00000000-0000-4000-8000-000000000031@203.0.113.31:443?security=tls&sni=a.example.com#Alpha",
            "trojan://synthetic-password@198.51.100.32:443?sni=b.example.com#Bravo",
            "tuic://00000000-0000-4000-8000-000000000033@203.0.113.33:443#Charlie",
        ).joinToString("\n")
    }
}
