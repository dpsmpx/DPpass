package com.dpsmpx.dppass.app.ui

import android.app.AlertDialog
import android.text.InputType
import android.view.Gravity
import android.view.View
import com.dpsmpx.dppass.R
import com.dpsmpx.dppass.app.TunnelStatus
import com.dpsmpx.dppass.connection.ActivationResult
import com.dpsmpx.dppass.diagnostics.Outcome
import com.dpsmpx.dppass.routing.SiteListKind
import com.dpsmpx.dppass.routing.SiteLists
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * «Свои списки сайтов» (D-93): напрямую, через туннель, блокировать —
 * домены, geosite, адреса и geoip, правка рукой. Сохранение — смена
 * политики: активация с новыми правилами, отказ — с причиной у поля.
 */
class SiteListsScreen(host: Host) : SubScreen(host, R.string.site_lists_title) {
    private val body = Ui.column(context, 12)

    override fun content(): View = body

    override fun render(status: TunnelStatus) {
        val lists = host.graph?.core?.userPolicy?.currentOrDefault()?.lists ?: return
        body.removeAllViews()
        body.addView(
            Ui.listCard(context).apply {
                SiteListKind.entries.forEachIndexed { i, kind ->
                    if (i > 0) addView(Ui.divider(context))
                    val n = lists[kind].size
                    addView(
                        Ui.ListRow(context, icon(kind), context.getString(title(kind)))
                            .subtitle(context.resources.getQuantityString(R.plurals.site_list_count, n, n) + "\n" + context.getString(note(kind)))
                            .trailing(Ui.icon(context, R.drawable.ic_edit, R.color.text_secondary))
                            .onClick { edit(kind) },
                        Ui.matchWidth(),
                    )
                }
            },
            Ui.matchWidth(),
        )
        body.addView(Ui.text(context, R.style.Text_DPpass_Caption, context.getString(R.string.site_lists_note)))
    }

    /** Правка одного списка: запись на строку; неверная строка — ошибка у поля, окно не закрывается. */
    private fun edit(kind: SiteListKind) {
        val core = host.graph?.core ?: return
        val field = Ui.field(
            context,
            R.string.site_lists_hint,
            InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_FLAG_MULTI_LINE or InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS,
        ).apply {
            isSingleLine = false
            minLines = 4
            maxLines = 12
            gravity = Gravity.TOP or Gravity.START
            val p = Ui.dp(context, 12)
            setPadding(Ui.dp(context, 16), p, Ui.dp(context, 16), p)
            setText(core.userPolicy.currentOrDefault().lists[kind].format())
        }
        val form = Ui.column(context, 8).apply {
            val p = Ui.dp(context, 24)
            setPadding(p, Ui.dp(context, 8), p, 0)
            addView(Ui.text(context, R.style.Text_DPpass_Secondary, context.getString(note(kind))), Ui.matchWidth())
            addView(field, Ui.matchWidth())
        }
        val dialog = AlertDialog.Builder(context)
            .setTitle(title(kind))
            .setView(form)
            .setPositiveButton(R.string.action_save, null)
            .setNegativeButton(android.R.string.cancel, null)
            .show()
        Ui.secure(dialog)
        dialog.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener {
            host.scope.launch {
                val r = withContext(Dispatchers.IO) { core.userPolicy.setSiteLists(mapOf(kind to field.text.toString())) }
                if (r is Outcome.Failure) {
                    field.error = r.errors.first().message
                    return@launch
                }
                dialog.dismiss()
                applied(host, r)
            }
        }
    }

    companion object {
        fun title(kind: SiteListKind): Int = when (kind) {
            SiteListKind.DIRECT -> R.string.site_list_direct
            SiteListKind.PROXY -> R.string.site_list_proxy
            SiteListKind.BLOCK -> R.string.site_list_block
        }

        private fun note(kind: SiteListKind): Int = when (kind) {
            SiteListKind.DIRECT -> R.string.site_list_direct_note
            SiteListKind.PROXY -> R.string.site_list_proxy_note
            SiteListKind.BLOCK -> R.string.site_list_block_note
        }

        private fun icon(kind: SiteListKind): Int = when (kind) {
            SiteListKind.DIRECT -> R.drawable.ic_route
            SiteListKind.PROXY -> R.drawable.ic_shield
            SiteListKind.BLOCK -> R.drawable.ic_block
        }

        /** «Напрямую 3 · через туннель 5 · блокировать 2» или «не заданы». */
        fun summary(host: Host, lists: SiteLists): String = if (lists.isEmpty) {
            host.activity.getString(R.string.site_lists_empty)
        } else {
            host.activity.getString(R.string.site_lists_summary, lists.direct.size, lists.proxy.size, lists.block.size)
        }

        /** Итог смены политики (D-38): отказ активации — с причиной; применено — туннель переподключается. */
        fun applied(host: Host, r: Outcome<ActivationResult?>, done: Int? = null) {
            val c = host.activity
            when (r) {
                is Outcome.Failure -> host.problem(c.getString(R.string.settings_not_applied), r.errors.first())
                is Outcome.Success -> when (val a = r.value) {
                    is ActivationResult.Rejected -> a.diagnostics.firstOrNull { it.isError }?.let {
                        host.problem(c.getString(R.string.settings_not_applied), it)
                    }
                    is ActivationResult.Activated -> {
                        done?.let { host.toast(c.getString(it)) }
                        host.reconnectIfBusy()
                    }
                    null -> done?.let { host.toast(c.getString(it)) }
                }
            }
            host.changed()
        }
    }
}
