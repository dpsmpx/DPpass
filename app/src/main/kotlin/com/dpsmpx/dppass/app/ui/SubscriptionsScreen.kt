package com.dpsmpx.dppass.app.ui

import android.app.AlertDialog
import android.content.ActivityNotFoundException
import android.content.Intent
import android.net.Uri
import android.text.TextUtils
import android.text.format.DateUtils
import android.view.View
import com.dpsmpx.dppass.R
import com.dpsmpx.dppass.app.TunnelStatus
import com.dpsmpx.dppass.core.Clock
import com.dpsmpx.dppass.core.SubscriptionId
import com.dpsmpx.dppass.diagnostics.DiagCode
import com.dpsmpx.dppass.diagnostics.Outcome
import com.dpsmpx.dppass.subscriptions.UpdatePolicy

/**
 * «Подписки» (D-36, D-39, D-42): список, добавление, применение,
 * обновление, трафик и срок, автообновление, идентификатор устройства
 * только по согласию (D-33), свои серверы, удаление. Применённая
 * подписка при поднятом туннеле переподключает его с новыми серверами.
 */
class SubscriptionsScreen(host: Host) : Screen(host) {
    private val list = Ui.column(context, 12)
    private val empty = Ui.card(context, 12).apply {
        addView(Ui.text(context, R.style.Text_DPpass_Body, context.getString(R.string.subs_empty)))
        addView(Ui.button(context, R.string.subs_add, Ui.Style.PRIMARY, R.drawable.ic_add).apply { setOnClickListener { ImportFlow.addSubscription(host) } })
        addView(Ui.button(context, R.string.import_clipboard, Ui.Style.OUTLINE, R.drawable.ic_paste).apply { setOnClickListener { ImportFlow.fromClipboard(host) } })
    }
    private val error = Ui.text(context, R.style.Text_DPpass_Secondary).apply { setTextColor(context.getColor(R.color.error)) }

    // История активаций (D-07): что применялось из подписок и своих конфигураций и почему нет.
    private val history = Ui.listCard(context).apply {
        addView(
            Ui.ListRow(context, R.drawable.ic_clock, context.getString(R.string.history_title))
                .subtitle(context.getString(R.string.history_entry_note))
                .trailing(Ui.icon(context, R.drawable.ic_chevron, R.color.text_secondary))
                .onClick { host.push(ActivationHistoryScreen(host)) },
            Ui.matchWidth(),
        )
    }

    override val view: View = scroll(
        Ui.column(context, 12).apply {
            addView(header(context.getString(R.string.tab_subscriptions), Ui.iconButton(context, R.drawable.ic_add, context.getString(R.string.add_title)) { ImportFlow.menu(host) }))
            addView(error)
            addView(empty, Ui.matchWidth())
            addView(list, Ui.matchWidth())
            addView(history, Ui.matchWidth())
        },
        topDp = 4,
    )

    override fun render(status: TunnelStatus) {
        val core = host.graph?.core ?: return
        val state = when (val s = core.subscriptions.state()) {
            is Outcome.Success -> s.value
            is Outcome.Failure -> {
                list.removeAllViews()
                error.text = context.getString(R.string.error_with_reason, context.getString(Ui.kind(s.errors.first().kind)), s.errors.first().message)
                error.visibility = View.VISIBLE
                empty.visibility = View.GONE
                return
            }
        }
        error.visibility = View.GONE
        val rows = SubscriptionList.rows(state, ConfigSource.of(core.activation.state.active?.source), Clock.SYSTEM.nowMillis())
        empty.visibility = if (rows.isEmpty()) View.VISIBLE else View.GONE
        list.removeAllViews()
        rows.forEach { list.addView(card(it), Ui.matchWidth()) }
    }

    private fun card(r: SubscriptionRow): View = Ui.card(context, 8).apply {
        val head = Ui.row(context)
        head.addView(Ui.iconAvatar(context, if (r.inline) R.drawable.ic_link else R.drawable.ic_subscriptions))
        val titles = Ui.column(context, 2)
        titles.addView(
            Ui.text(context, R.style.Text_DPpass_Title, r.name).apply {
                maxLines = 2
                ellipsize = TextUtils.TruncateAt.END
            },
        )
        titles.addView(Ui.text(context, R.style.Text_DPpass_Caption, summary(r)))
        head.addView(titles, Ui.weight().apply { marginStart = Ui.dp(context, 12) })
        head.addView(Ui.iconButton(context, R.drawable.ic_more, context.getString(R.string.subs_menu, r.name), R.color.text_secondary) { menu(r) })
        addView(head, Ui.matchWidth())

        val chips = Ui.row(context, 6)
        if (r.active) chips.addView(Ui.chip(context, context.getString(R.string.subs_active), R.color.success_container, R.color.success))
        if (r.inline) chips.addView(Ui.chip(context, context.getString(R.string.subs_inline), R.color.surface_variant, R.color.text_secondary))
        if (r.deviceIdEnabled) chips.addView(Ui.chip(context, context.getString(R.string.subs_device_id_on), R.color.surface_variant, R.color.text_secondary))
        if (chips.childCount > 0) addView(chips)

        r.usedBytes?.let { used ->
            val total = r.totalBytes
            val text = if (total != null) context.getString(R.string.subs_traffic, bytes(used), bytes(total)) else context.getString(R.string.subs_traffic_unlimited, bytes(used))
            addView(Ui.text(context, R.style.Text_DPpass_Secondary, text))
            r.usedPercent?.let { pct -> addView(Ui.Meter(context).apply { fraction = pct / 100f }, Ui.matchWidth()) }
        }
        r.expireMillis?.let { at ->
            val text = when {
                r.expired -> context.getString(R.string.subs_expired, date(at))
                r.daysLeft != null -> context.getString(R.string.subs_expires_in, date(at), context.resources.getQuantityString(R.plurals.days, r.daysLeft.toInt(), r.daysLeft.toInt()))
                else -> context.getString(R.string.subs_expires, date(at))
            }
            val warn = r.expired || (r.daysLeft != null && r.daysLeft <= 3)
            addView(Ui.text(context, R.style.Text_DPpass_Secondary, text).apply { if (warn) setTextColor(context.getColor(if (r.expired) R.color.error else R.color.warning)) })
        }
        r.failure?.let { f ->
            if (f.code == DiagCode.SUBSCRIPTION_DEVICE_ID_REQUIRED && !r.deviceIdEnabled) {
                // Понятная причина и одно действие вместо текста отказа: что делать — ясно и так.
                addView(Ui.text(context, R.style.Text_DPpass_Secondary, context.getString(R.string.subs_device_id_needed)).apply { setTextColor(context.getColor(R.color.error)) })
                addView(
                    Ui.button(context, R.string.subs_device_id_enable, Ui.Style.OUTLINE, R.drawable.ic_key).apply {
                        setOnClickListener { deviceId(r, true) }
                    },
                )
            } else {
                addView(
                    Ui.text(context, R.style.Text_DPpass_Secondary, context.getString(R.string.subs_failed, context.getString(Ui.kind(f.kind)))).apply {
                        setTextColor(context.getColor(R.color.error))
                    },
                )
                addView(Ui.text(context, R.style.Text_DPpass_Caption, f.message).apply { setTextIsSelectable(true) })
            }
        }
        r.announce?.let { addView(Ui.text(context, R.style.Text_DPpass_Caption, context.getString(R.string.subs_announce, it))) }

        val busy = r.id in ImportFlow.running
        val action = if (r.active) R.string.subs_refresh else R.string.subs_apply
        addView(
            Ui.button(context, if (busy) R.string.subs_refreshing else action, if (r.active) Ui.Style.TONAL else Ui.Style.PRIMARY, R.drawable.ic_refresh).apply {
                isEnabled = !busy
                alpha = if (busy) 0.6f else 1f
                setOnClickListener { refresh(r.id, r.name) }
            },
            Ui.matchWidth().apply { topMargin = Ui.dp(context, 4) },
        )
    }

    private fun summary(r: SubscriptionRow): String {
        val parts = mutableListOf<String>()
        r.profileCount?.let { n -> parts += context.resources.getQuantityString(R.plurals.servers_count, n, n) }
        parts += r.updatedAtMillis?.let { at ->
            context.getString(R.string.subs_updated, DateUtils.getRelativeTimeSpanString(at, Clock.SYSTEM.nowMillis(), DateUtils.MINUTE_IN_MILLIS))
        } ?: context.getString(R.string.subs_never)
        if (!r.inline) {
            parts += r.autoUpdateMinutes?.let { context.getString(R.string.subs_auto_every, it / 60) } ?: context.getString(R.string.subs_auto_off)
        }
        return parts.joinToString(ServerList.SEPARATOR)
    }

    /** Меню подписки: всё, что меняется реже, чем «обновить». */
    private fun menu(r: SubscriptionRow) {
        val items = Ui.listCard(context)
        lateinit var sheet: android.app.Dialog
        fun item(icon: Int, title: Int, subtitle: CharSequence? = null, action: () -> Unit) {
            if (items.childCount > 0) items.addView(Ui.divider(context))
            items.addView(Ui.ListRow(context, icon, context.getString(title)).subtitle(subtitle).onClick { sheet.dismiss(); action() }, Ui.matchWidth())
        }
        item(R.drawable.ic_refresh, if (r.active) R.string.subs_refresh else R.string.subs_apply) { refresh(r.id, r.name) }
        item(R.drawable.ic_edit, R.string.subs_rename) { rename(r) }
        if (!r.inline) {
            item(
                R.drawable.ic_clock,
                R.string.subs_auto_title,
                (r.autoUpdateMinutes?.let { context.getString(R.string.subs_auto_every, it / 60) } ?: context.getString(R.string.subs_auto_off)) +
                    (r.providerIntervalHours?.let { "\n" + context.getString(R.string.subs_provider_interval, it) } ?: ""),
            ) { interval(r) }
            item(R.drawable.ic_key, R.string.subs_device_id, context.getString(if (r.deviceIdEnabled) R.string.subs_device_id_on else R.string.subs_device_id_off)) {
                deviceIdSheet(r)
            }
        }
        r.pageUrl?.let { url -> item(R.drawable.ic_open, R.string.subs_open_page, Uri.parse(url).host) { open(url) } }
        r.supportUrl?.let { url -> item(R.drawable.ic_open, R.string.subs_open_support, Uri.parse(url).host) { open(url) } }
        item(R.drawable.ic_delete, R.string.subs_remove) {
            confirm(context.getString(R.string.subs_remove_confirm, r.name)) { edit { host.graph?.core?.subscriptions?.remove(r.id) } }
        }
        sheet = Ui.sheet(context, r.name, items)
        sheet.show()
    }

    private fun interval(r: SubscriptionRow) {
        val items = Ui.listCard(context)
        lateinit var sheet: android.app.Dialog
        UpdatePolicy.CHOICES_MINUTES.forEachIndexed { i, minutes ->
            if (i > 0) items.addView(Ui.divider(context))
            val label = minutes?.let { context.getString(R.string.subs_auto_every, it / 60) } ?: context.getString(R.string.subs_auto_off)
            items.addView(
                Ui.radioRow(context, label, null, minutes == r.autoUpdateMinutes) {
                    sheet.dismiss()
                    edit { host.graph?.core?.subscriptions?.setUpdateInterval(r.id, minutes) }
                },
                Ui.matchWidth(),
            )
        }
        val body = Ui.column(context, 8).apply {
            addView(items, Ui.matchWidth())
            addView(Ui.text(context, R.style.Text_DPpass_Caption, context.getString(R.string.subs_auto_note)).apply { setPadding(Ui.dp(context, 4), 0, Ui.dp(context, 4), 0) })
        }
        sheet = Ui.sheet(context, context.getString(R.string.subs_auto_title), body)
        sheet.show()
    }

    /** Идентификатор устройства — только по согласию (D-33): объяснение, переключатель, сброс. */
    private fun deviceIdSheet(r: SubscriptionRow) {
        lateinit var sheet: android.app.Dialog
        val body = Ui.column(context, 8).apply {
            addView(Ui.text(context, R.style.Text_DPpass_Secondary, context.getString(R.string.subs_device_id_note)).apply { setPadding(Ui.dp(context, 4), 0, Ui.dp(context, 4), 0) })
            val card = Ui.listCard(context)
            card.addView(
                Ui.switchRow(context, R.drawable.ic_key, context.getString(R.string.subs_device_id), null, r.deviceIdEnabled) { on ->
                    sheet.dismiss()
                    deviceId(r, on)
                },
                Ui.matchWidth(),
            )
            if (r.deviceIdEnabled) {
                card.addView(Ui.divider(context))
                card.addView(
                    Ui.ListRow(context, R.drawable.ic_refresh, context.getString(R.string.subs_device_id_reset)).onClick {
                        sheet.dismiss()
                        confirm(context.getString(R.string.subs_device_id_reset_confirm)) { edit { host.graph?.core?.subscriptions?.resetDeviceId(r.id) } }
                    },
                    Ui.matchWidth(),
                )
            }
            addView(card, Ui.matchWidth())
        }
        sheet = Ui.sheet(context, context.getString(R.string.subs_device_id), body)
        sheet.show()
    }

    private fun deviceId(r: SubscriptionRow, on: Boolean) {
        edit { host.graph?.core?.subscriptions?.setDeviceId(r.id, on) }
        // Включили, потому что поставщик требует, — сразу загрузить заново.
        if (on && r.failure?.code == DiagCode.SUBSCRIPTION_DEVICE_ID_REQUIRED) refresh(r.id, r.name)
    }

    private fun rename(r: SubscriptionRow) {
        val field = Ui.field(context, R.string.subs_name_hint).apply { setText(r.name) }
        val form = Ui.column(context, 8).apply {
            val p = Ui.dp(context, 24)
            setPadding(p, Ui.dp(context, 8), p, 0)
            addView(field, Ui.matchWidth())
        }
        Ui.secure(
            AlertDialog.Builder(context)
                .setTitle(R.string.subs_rename)
                .setView(form)
                .setPositiveButton(R.string.action_save) { _, _ -> edit { host.graph?.core?.subscriptions?.rename(r.id, field.text.toString()) } }
                .setNegativeButton(android.R.string.cancel, null)
                .show(),
        )
    }

    /** Страница поставщика — во внешнем браузере; адрес только `https://` (`MetadataParser`). */
    private fun open(url: String) {
        if (!url.startsWith("https://")) return
        try {
            context.startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(url)).addCategory(Intent.CATEGORY_BROWSABLE))
        } catch (e: ActivityNotFoundException) {
            host.toast(context.getString(R.string.no_browser))
        }
    }

    private fun refresh(id: SubscriptionId, name: String) = ImportFlow.refresh(host, id, name)

    /** Правка, которая сохраняется сразу (D-36); отказ хранилища — с причиной. */
    private fun edit(change: () -> Outcome<*>?) {
        when (val r = change()) {
            is Outcome.Failure -> host.problem(context.getString(Ui.kind(r.errors.first().kind)), r.errors.first())
            else -> Unit
        }
        host.changed()
    }

    private fun confirm(message: String, action: () -> Unit) {
        Ui.secure(
            AlertDialog.Builder(context)
                .setMessage(message)
                .setPositiveButton(android.R.string.ok) { _, _ -> action() }
                .setNegativeButton(android.R.string.cancel, null)
                .show(),
        )
    }
}
