package com.dpsmpx.dppass.app.ui

import android.app.Dialog
import android.view.View
import com.dpsmpx.dppass.R
import com.dpsmpx.dppass.app.TunnelStatus
import com.dpsmpx.dppass.connection.HappRoutingImport
import com.dpsmpx.dppass.connection.ProviderListsView
import com.dpsmpx.dppass.core.SubscriptionId
import com.dpsmpx.dppass.routing.SiteListKind
import com.dpsmpx.dppass.routing.SiteLists
import com.dpsmpx.dppass.routing.SiteListsChange
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * «Списки поставщика» подписки (D-94): профиль маршрутизации, который
 * прислал поставщик, хранится рядом со своими списками. Здесь — что в нём,
 * что не взято и почему, что изменилось с прошлым профилем; включить их
 * можно только после подтверждения (D-11). Свои списки — поверх.
 */
class ProviderListsScreen(host: Host, private val subscription: SubscriptionId) : SubScreen(host, R.string.provider_lists_title) {
    private val body = Ui.column(context, 12)

    override fun content(): View = body

    override fun render(status: TunnelStatus) {
        val core = host.graph?.core ?: return
        val sub = core.subscriptions.state().valueOrNull()?.find(subscription) ?: return host.pop()
        val view = core.providerLists(sub) ?: return host.pop()
        body.removeAllViews()
        val profile = view.profile
        val head = profile?.name?.let { context.getString(R.string.provider_lists_named, it) } ?: sub.displayName
        body.addView(Ui.text(context, R.style.Text_DPpass_Body, head))
        body.addView(Ui.text(context, R.style.Text_DPpass_Caption, context.getString(R.string.provider_lists_received, dateTime(view.receivedAtMillis))))
        body.addView(
            Ui.listCard(context).apply {
                addView(
                    Ui.switchRow(
                        context,
                        R.drawable.ic_route,
                        context.getString(R.string.provider_lists_use),
                        context.getString(R.string.provider_lists_use_note),
                        view.inUse,
                    ) { on -> if (on) confirm(view, sub.displayName) else use(false) },
                    Ui.matchWidth(),
                )
            },
            Ui.matchWidth(),
        )
        if (view.inUse && !view.applied) body.addView(Ui.text(context, R.style.Text_DPpass_Secondary, context.getString(R.string.provider_lists_not_applied)))
        view.problem?.let {
            body.addView(
                Ui.text(context, R.style.Text_DPpass_Secondary, context.getString(R.string.provider_lists_problem, it.message)).apply {
                    setTextColor(context.getColor(R.color.error))
                },
            )
        }
        if (profile != null) {
            body.addView(lists(profile.lists), Ui.matchWidth())
            body.addView(changes(view), Ui.matchWidth())
            if (profile.skipped.isNotEmpty()) body.addView(skipped(profile), Ui.matchWidth())
        }
        body.addView(
            Ui.button(context, R.string.subs_refresh, Ui.Style.TONAL, R.drawable.ic_refresh).apply {
                setOnClickListener { ImportFlow.refresh(host, subscription, sub.displayName) }
            },
            Ui.matchWidth(),
        )
    }

    /** Три списка профиля: сколько записей; по нажатию — сами записи. */
    private fun lists(lists: SiteLists): View = Ui.listCard(context).apply {
        SiteLists.ORDER.forEachIndexed { i, kind ->
            if (i > 0) addView(Ui.divider(context))
            val n = lists[kind].size
            addView(
                Ui.ListRow(context, null, context.getString(SiteListsScreen.title(kind)))
                    .subtitle(context.resources.getQuantityString(R.plurals.site_list_count, n, n))
                    .onClick { entries(context.getString(SiteListsScreen.title(kind)), lists[kind].format()) },
                Ui.matchWidth(),
            )
        }
    }

    /** Что изменилось с прошлым профилем: по спискам — добавлено и убрано. */
    private fun changes(view: ProviderListsView): View = Ui.listCard(context).apply {
        val change = view.change
        val subtitle = when {
            change == null -> context.getString(R.string.provider_lists_first)
            change.isEmpty -> context.getString(R.string.provider_lists_no_changes)
            else -> SiteLists.ORDER.mapNotNull { kind ->
                val added = change.added[kind].size
                val removed = change.removed[kind].size
                val title = context.getString(SiteListsScreen.title(kind))
                if (added == 0 && removed == 0) null else context.getString(R.string.provider_lists_change_row, title, added, removed)
            }.joinToString("\n")
        } + (view.previousAtMillis?.let { "\n" + context.getString(R.string.provider_lists_changes_since, dateTime(it)) } ?: "")
        val row = Ui.ListRow(context, R.drawable.ic_clock, context.getString(R.string.provider_lists_changes)).subtitle(subtitle)
        if (change != null && !change.isEmpty) row.onClick { entries(context.getString(R.string.provider_lists_changes), describe(change)) }
        addView(row, Ui.matchWidth())
    }

    private fun skipped(profile: HappRoutingImport): View = Ui.listCard(context).apply {
        val n = profile.skipped.size
        addView(
            Ui.ListRow(context, R.drawable.ic_info, context.resources.getQuantityString(R.plurals.provider_lists_skipped, n, n))
                .onClick { entries(context.getString(R.string.import_happ_skipped), profile.skipped.joinToString("\n") { "• ${it.field}: ${it.reason}" }) },
            Ui.matchWidth(),
        )
    }

    private fun describe(change: SiteListsChange): String = SiteLists.ORDER.flatMap { kind ->
        val title = context.getString(SiteListsScreen.title(kind))
        listOfNotNull(
            change.added[kind].takeIf { !it.isEmpty }?.let { "${context.getString(R.string.provider_lists_added, title)}\n${it.format()}" },
            change.removed[kind].takeIf { !it.isEmpty }?.let { "${context.getString(R.string.provider_lists_removed, title)}\n${it.format()}" },
        )
    }.joinToString("\n\n")

    private fun entries(title: String, text: String) {
        val shown = text.ifEmpty { context.getString(R.string.provider_lists_empty_list) }
        Ui.sheet(host.activity, title, Ui.text(context, R.style.Text_DPpass_Secondary, shown).apply { setTextIsSelectable(true) }).show()
    }

    /** Включение — только после того, как пользователь увидел, что в списках (D-11). */
    private fun confirm(view: ProviderListsView, name: String) {
        val lists = view.profile?.lists ?: return host.changed()
        lateinit var sheet: Dialog
        var chosen = false
        val content = Ui.column(context, 12).apply {
            val summary = context.getString(R.string.provider_lists_confirm, lists.direct.size, lists.proxy.size, lists.block.size)
            addView(Ui.text(context, R.style.Text_DPpass_Body, summary))
            addView(Ui.text(context, R.style.Text_DPpass_Caption, context.getString(R.string.provider_lists_use_note)))
            addView(
                Ui.button(context, R.string.provider_lists_enable, Ui.Style.PRIMARY, R.drawable.ic_check).apply {
                    setOnClickListener {
                        chosen = true
                        sheet.dismiss()
                        use(true)
                    }
                },
                Ui.matchWidth(),
            )
        }
        sheet = Ui.sheet(host.activity, context.getString(R.string.provider_lists_confirm_title, name), content)
        // Закрыли без выбора — переключатель возвращается в прежнее положение.
        sheet.setOnDismissListener { if (!chosen) host.changed() }
        sheet.show()
    }

    private fun use(on: Boolean) {
        val core = host.graph?.core ?: return
        host.scope.launch {
            val r = withContext(Dispatchers.IO) { core.subscriptions.setUseProviderLists(subscription, on) }
            SiteListsScreen.applied(host, r, if (on) R.string.provider_lists_on_done else R.string.provider_lists_off_done)
        }
    }

    companion object {
        /** Строка «Почему этот маршрут» о списке поставщика (D-94). */
        fun why(kind: SiteListKind): Int = when (kind) {
            SiteListKind.DIRECT -> R.string.route_why_provider_direct
            SiteListKind.PROXY -> R.string.route_why_provider_proxy
            SiteListKind.BLOCK -> R.string.route_why_provider_block
        }
    }
}
