package com.dpsmpx.dppass.desktop

import com.dpsmpx.dppass.connection.HappRouting
import com.dpsmpx.dppass.connection.ProviderListsView
import com.dpsmpx.dppass.core.SubscriptionId
import com.dpsmpx.dppass.desktop.ui.ProviderListsDialog
import com.dpsmpx.dppass.routing.SiteListsChange
import kotlin.test.Test
import kotlin.test.assertTrue

/** Окно «Списки поставщика» на ПК (D-94): что в профиле, действует ли, что изменилось и что не взято. Данные синтетические. */
class ProviderListsDialogTest {
    private val old = HappRouting.provider("""{"Name":"P","DirectSites":["example.ru"]}""").valueOrNull()!!
    private val now = HappRouting.provider("""{"Name":"P","DirectSites":["example.org"],"BlockSites":["ads.example.net"],"FakeDNS":"true"}""").valueOrNull()!!

    private fun view(inUse: Boolean, applied: Boolean, change: SiteListsChange?) =
        ProviderListsView(SubscriptionId("s1"), now, null, 1_000, change, if (change != null) 500 else null, inUse, applied)

    @Test
    fun textShowsListsChangesAndWhatIsNotTaken() {
        val text = ProviderListsDialog.describe(view(inUse = false, applied = true, SiteListsChange.between(old.lists, now.lists)), "Synthetic")
        assertTrue("Профиль «P»" in text, text)
        assertTrue("Не используются" in text, text)
        assertTrue("Напрямую — 1:\nexample.org" in text, text)
        assertTrue("+ «Напрямую»: example.org" in text && "− «Напрямую»: example.ru" in text, text)
        assertTrue("+ «Блокировать»: ads.example.net" in text, text)
        assertTrue("• FakeDNS:" in text, text)
    }

    @Test
    fun stateIsSaidPlainly() {
        assertTrue("сравнивать пока не с чем" in ProviderListsDialog.describe(view(inUse = true, applied = true, null), "Synthetic"))
        assertTrue("Свои списки сайтов — поверх" in ProviderListsDialog.describe(view(inUse = true, applied = true, null), "Synthetic"))
        assertTrue("подписка не применена" in ProviderListsDialog.describe(view(inUse = true, applied = false, null), "Synthetic"))
        val same = SiteListsChange.between(now.lists, now.lists)
        assertTrue("ничего не изменилось" in ProviderListsDialog.describe(view(inUse = true, applied = true, same), "Synthetic"))
    }
}
