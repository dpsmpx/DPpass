package com.dpsmpx.dppass.app.paths

import android.widget.EditText
import com.dpsmpx.dppass.R
import com.dpsmpx.dppass.app.device.expect
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

/**
 * Ключевой путь «свои списки сайтов» (D-93): профиль маршрутизации Happ из
 * буфера обмена → сводка, что добавится и что не будет взято и почему →
 * «Добавить в свои списки» → списки в «Настройках»; правка рукой — неверная
 * строка остаётся в окне с причиной. Коды geosite/geoip сверяет набор
 * геоданных настоящего ядра. Данные синтетические.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [26, 29, 36])
class SiteListsPathTest {
    @Test
    fun happProfileFillsOwnListsAndListsAreEditable() {
        Act().use { act ->
            val c = act.context
            val a = act.launch()
            act.clipboard(PROFILE)
            act.tap(a, c.getString(R.string.tab_subscriptions))
            act.tap(a, c.getString(R.string.add_title))
            act.tap(a, c.getString(R.string.import_clipboard))

            act.waitFor(a, c.getString(R.string.import_happ_summary, 1, 2, 1))
            expect(act.shows(a, c.getString(R.string.import_happ_skipped))) { "нет списка невзятого: ${act.texts(a)}" }
            expect(act.shows(a, "RemoteDNSType")) { "DNS профиля не назван невзятым: ${act.texts(a)}" }
            expect(act.shows(a, "geoip:zz-synthetic")) { "код вне набора не назван: ${act.texts(a)}" }
            expect(act.graph(a).core.userPolicy.currentOrDefault().lists.isEmpty) { "списки изменились до нажатия (T13)" }
            act.tap(a, c.getString(R.string.import_happ_add))
            act.d.waitUntil("списки добавлены") { !act.graph(a).core.userPolicy.currentOrDefault().lists.isEmpty }

            act.tap(a, c.getString(R.string.tab_settings))
            act.waitFor(a, c.getString(R.string.site_lists_summary, 1, 2, 1))
            act.tap(a, c.getString(R.string.site_lists_title))
            act.tap(a, c.getString(R.string.site_list_block))
            act.type(a, c.getString(R.string.site_lists_hint), "ads.example.net\nregexp:^x")
            act.tap(a, c.getString(R.string.action_save))
            act.d.waitUntil("неверная строка — причина у поля") { act.view(a, EditText::class.java)?.error?.startsWith("строка 2") == true }
            expect(act.graph(a).core.userPolicy.currentOrDefault().lists.block.size == 1) { "неверный список сохранён" }
            act.type(a, c.getString(R.string.site_lists_hint), "ads.example.net\ntracker.example.org")
            act.tap(a, c.getString(R.string.action_save))
            act.d.waitUntil("список сохранён") { act.graph(a).core.userPolicy.currentOrDefault().lists.block.size == 2 }
            act.waitFor(a, c.resources.getQuantityString(R.plurals.site_list_count, 2, 2))
        }
    }

    private companion object {
        val PROFILE = """
            {
              "Name": "Synthetic",
              "GlobalProxy": "true",
              "RemoteDNSType": "DoH",
              "RemoteDNSIP": "192.0.2.53",
              "DirectSites": ["example.ru"],
              "ProxySites": ["geosite:category-ru", "full:www.example.com"],
              "ProxyIp": ["geoip:zz-synthetic"],
              "BlockSites": ["ads.example.net"]
            }
        """.trimIndent()
    }
}
