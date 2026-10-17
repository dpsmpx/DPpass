package com.dpsmpx.dppass.app.ui

import android.app.AlertDialog
import android.app.Dialog
import android.text.InputType
import android.view.View
import com.dpsmpx.dppass.R
import com.dpsmpx.dppass.app.RelayNetworks
import com.dpsmpx.dppass.app.TunnelState
import com.dpsmpx.dppass.app.TunnelStatus
import com.dpsmpx.dppass.connection.RelayDevice
import com.dpsmpx.dppass.connection.RelayDraft
import com.dpsmpx.dppass.diagnostics.Outcome
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * «Устройства раздачи» (D-55): подключение через другой телефон с DPpass,
 * который раздаёт свой туннель (D-51). Доверенное устройство выбирается
 * одним нажатием — и сразу подключение. Какие из них рядом, видно по
 * шлюзам сетей телефона (Wi-Fi, Bluetooth, USB): телефон спрашивает шлюз
 * по протоколу входа, ничего не объявляя в сети. Добавить — вручную или
 * ссылкой «Поделиться входом» с того телефона.
 */
class RelaysScreen(host: Host) : SubScreen(host, R.string.relays_title) {
    private val body = Ui.column(context, 12)
    private var found: Map<String, RelayNetworks.Target> = emptyMap()
    private var gateways: List<RelayNetworks.Gateway> = emptyList()
    private var checking = false
    private var scan: Job? = null

    override fun content(): View = body

    override fun onShown() = rescan()

    override fun onHidden() {
        scan?.cancel()
        scan = null
    }

    override fun render(status: TunnelStatus) {
        body.removeAllViews()
        body.addView(caption(R.string.relays_intro))
        val core = host.graph?.core ?: return
        val devices = when (val l = core.relays.list()) {
            is Outcome.Failure -> {
                body.addView(Ui.card(context).apply { addView(Ui.text(context, R.style.Text_DPpass_Secondary, l.errors.first().message)) }, Ui.matchWidth())
                return
            }
            is Outcome.Success -> l.value
        }
        val selected = host.prefs.selectedRelay?.takeIf { id -> devices.any { it.id == id } }

        // ---- доверенные устройства ----
        body.addView(Ui.section(context, context.getString(R.string.relays_devices)))
        body.addView(
            Ui.listCard(context).apply {
                addView(Ui.radioRow(context, context.getString(R.string.relays_off), context.getString(R.string.relays_off_note), selected == null) { choose(null) }, Ui.matchWidth())
                for (d in devices) {
                    addView(Ui.divider(context))
                    val where = found[d.id]?.medium
                    val note = when {
                        where != null -> context.getString(R.string.relays_near, medium(where))
                        checking -> context.getString(R.string.relays_checking)
                        else -> context.getString(R.string.relays_absent)
                    }
                    addView(
                        Ui.radioRow(context, d.name, note, selected == d.id) { choose(d.id) }
                            .trailing(Ui.iconButton(context, R.drawable.ic_more, context.getString(R.string.relays_actions)) { actions(d) }),
                        Ui.matchWidth(),
                    )
                }
            },
            Ui.matchWidth(),
        )
        body.addView(Ui.button(context, R.string.relays_add, Ui.Style.TONAL, R.drawable.ic_add).apply { setOnClickListener { add(host, null) { rescan() } } }, Ui.matchWidth())
        body.addView(Ui.button(context, R.string.import_clipboard, Ui.Style.OUTLINE, R.drawable.ic_paste).apply { setOnClickListener { ImportFlow.fromClipboard(host) } }, Ui.matchWidth())

        // ---- сети рядом: шлюзы, где не ответило ни одно известное устройство ----
        body.addView(Ui.section(context, context.getString(R.string.relays_networks)))
        val others = gateways.filter { g -> found.values.none { it.network == g.network && it.address == g.address } }
        when {
            checking && gateways.isEmpty() -> body.addView(caption(R.string.relays_checking))
            others.isEmpty() && gateways.isEmpty() -> body.addView(caption(R.string.relays_no_networks))
            others.isNotEmpty() -> body.addView(
                Ui.listCard(context).apply {
                    for ((i, g) in others.withIndex()) {
                        if (i > 0) addView(Ui.divider(context))
                        addView(
                            Ui.ListRow(context, R.drawable.ic_lan, context.getString(R.string.relays_gateway, medium(g.medium), g.address.toString()))
                                .subtitle(context.getString(R.string.relays_gateway_note))
                                .onClick { add(host, context.getString(R.string.relays_name_on, medium(g.medium))) { rescan() } },
                            Ui.matchWidth(),
                        )
                    }
                },
                Ui.matchWidth(),
            )
        }
        body.addView(Ui.button(context, R.string.relays_rescan, Ui.Style.TEXT, R.drawable.ic_refresh).apply { setOnClickListener { rescan() } })

        // ---- честные пределы (D-13) ----
        body.addView(Ui.section(context, context.getString(R.string.share_limits)))
        body.addView(Ui.card(context).apply { addView(Ui.text(context, R.style.Text_DPpass_Secondary, context.getString(R.string.relays_limits_text))) }, Ui.matchWidth())
    }

    /** Выбор сохраняется; туннель есть — переподключение через выбранное, нет — подключение сразу. */
    private fun choose(id: String?) {
        if (id == host.prefs.selectedRelay) return
        host.prefs.selectedRelay = id
        if (TunnelState.status.value.busy) host.reconnectIfBusy() else if (id != null) host.connect()
        host.changed()
    }

    /** Какие устройства рядом и какие шлюзы есть: в фоне, до двух коротких соединений на сеть и устройство. */
    private fun rescan() {
        val core = host.graph?.core ?: return
        val devices = core.relays.list().valueOrNull().orEmpty()
        scan?.cancel()
        checking = true
        render(TunnelState.status.value)
        scan = host.scope.launch {
            val (gws, answered) = withContext(Dispatchers.IO) {
                val gws = RelayNetworks.gateways(context)
                val answered = if (gws.isEmpty() && devices.none { it.address != null }) {
                    emptyMap()
                } else {
                    devices.mapNotNull { d -> RelayNetworks.locate(context, d).valueOrNull()?.let { d.id to it } }.toMap()
                }
                gws to answered
            }
            gateways = gws
            found = answered
            checking = false
            render(TunnelState.status.value)
        }
    }

    private fun actions(d: RelayDevice) {
        Ui.secure(
            AlertDialog.Builder(context)
                .setTitle(d.name)
                .setItems(arrayOf(context.getString(R.string.subs_rename), context.getString(R.string.relays_delete))) { _, which ->
                    if (which == 0) rename(d) else confirmDelete(d)
                }
                .show(),
        )
    }

    private fun rename(d: RelayDevice) {
        val name = Ui.field(context, R.string.relays_name_hint).apply { setText(d.name) }
        lateinit var sheet: Dialog
        val content = Ui.column(context, 12).apply {
            addView(name, Ui.matchWidth())
            addView(
                Ui.button(context, R.string.action_save, Ui.Style.PRIMARY, R.drawable.ic_check).apply {
                    setOnClickListener {
                        val core = host.graph?.core ?: return@setOnClickListener
                        when (val r = core.relays.rename(d.id, name.text.toString())) {
                            is Outcome.Failure -> host.problem(context.getString(Ui.kind(r.errors.first().kind)), r.errors.first())
                            is Outcome.Success -> {
                                sheet.dismiss()
                                host.changed()
                            }
                        }
                    }
                },
                Ui.matchWidth(),
            )
        }
        sheet = Ui.sheet(context, context.getString(R.string.subs_rename), content)
        sheet.show()
    }

    private fun confirmDelete(d: RelayDevice) {
        Ui.secure(
            AlertDialog.Builder(context)
                .setMessage(context.getString(R.string.relays_delete_confirm, d.name))
                .setPositiveButton(R.string.relays_delete) { _, _ ->
                    val core = host.graph?.core ?: return@setPositiveButton
                    when (val r = core.relays.remove(d.id)) {
                        is Outcome.Failure -> host.problem(context.getString(Ui.kind(r.errors.first().kind)), r.errors.first())
                        is Outcome.Success -> {
                            if (host.prefs.selectedRelay == d.id) choose(null)
                            host.changed()
                        }
                    }
                }
                .setNegativeButton(android.R.string.cancel, null)
                .show(),
        )
    }

    private fun medium(m: RelayNetworks.Medium): String = context.getString(
        when (m) {
            RelayNetworks.Medium.WIFI -> R.string.relays_medium_wifi
            RelayNetworks.Medium.BLUETOOTH -> R.string.relays_medium_bluetooth
            RelayNetworks.Medium.USB -> R.string.relays_medium_usb
        },
    )

    private fun caption(text: Int): View =
        Ui.text(context, R.style.Text_DPpass_Caption, context.getString(text)).apply { setPadding(Ui.dp(context, 4), 0, Ui.dp(context, 4), 0) }

    companion object {
        /**
         * Ввод устройства вручную: имя, адрес (пусто — шлюз сети), порт, логин,
         * пароль — с экрана «Раздача туннеля» того телефона. Отказ — причина,
         * окно остаётся: опечатку можно исправить, не вводя всё заново.
         */
        fun add(host: Host, prefillName: String?, done: () -> Unit) {
            val c = host.activity
            val name = Ui.field(c, R.string.relays_name_hint).apply { setText(prefillName ?: c.getString(R.string.relays_default_name)) }
            val address = Ui.field(c, R.string.relays_address_hint, InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_URI)
            val port = Ui.field(c, R.string.share_port, InputType.TYPE_CLASS_NUMBER)
            val user = Ui.field(c, R.string.share_user, InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_VISIBLE_PASSWORD)
            val password = Ui.field(c, R.string.share_password, InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_VISIBLE_PASSWORD)
            lateinit var sheet: Dialog
            val content = Ui.column(c, 12).apply {
                for (f in listOf(name, address, port, user, password)) addView(f, Ui.matchWidth())
                addView(Ui.text(c, R.style.Text_DPpass_Caption, c.getString(R.string.relays_add_note)))
                addView(
                    Ui.button(c, R.string.action_save, Ui.Style.PRIMARY, R.drawable.ic_check).apply {
                        setOnClickListener {
                            val core = host.graph?.core ?: return@setOnClickListener
                            val draft = RelayDraft(
                                name.text.toString(),
                                address.text.toString(),
                                port.text.toString().trim().toIntOrNull() ?: 0,
                                user.text.toString(),
                                password.text.toString(),
                            )
                            when (val r = core.relays.add(draft)) {
                                is Outcome.Failure -> host.problem(c.getString(Ui.kind(r.errors.first().kind)), r.errors.first())
                                is Outcome.Success -> {
                                    sheet.dismiss()
                                    host.toast(c.getString(R.string.relays_added))
                                    done()
                                }
                            }
                        }
                    },
                    Ui.matchWidth(),
                )
            }
            sheet = Ui.sheet(c, c.getString(R.string.relays_add_title), content)
            sheet.show()
        }
    }
}
