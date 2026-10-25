package com.dpsmpx.dppass.app.ui

import android.app.AlertDialog
import android.app.Dialog
import android.content.ActivityNotFoundException
import android.content.Intent
import android.os.Build
import android.provider.Settings
import android.text.format.DateFormat
import android.view.View
import com.dpsmpx.dppass.R
import com.dpsmpx.dppass.app.PairingLink
import com.dpsmpx.dppass.app.TetherInterfaces
import com.dpsmpx.dppass.app.TunnelState
import com.dpsmpx.dppass.app.TunnelStatus
import com.dpsmpx.dppass.connection.PairedDevice
import com.dpsmpx.dppass.connection.Pairing
import com.dpsmpx.dppass.connection.RelayLink
import com.dpsmpx.dppass.connection.ShareService
import com.dpsmpx.dppass.connection.ShareSettings
import com.dpsmpx.dppass.diagnostics.DiagCode
import com.dpsmpx.dppass.diagnostics.Diagnostic
import com.dpsmpx.dppass.diagnostics.Outcome
import com.dpsmpx.dppass.diagnostics.map
import com.dpsmpx.dppass.engine.ShareSpec
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.IOException
import java.security.SecureRandom
import java.util.Date

/**
 * «Раздача» (D-51): пустить через туннель другие свои устройства — по
 * Wi-Fi (точка доступа), USB или Bluetooth. Телефон открывает на адресах
 * раздачи прокси SOCKS5/HTTP с логином и паролем; что указать на другом
 * устройстве — здесь. Логин и пароль видны только на этом экране: вся
 * активность под `FLAG_SECURE` (T9), в буфер они уходят с пометкой
 * «чувствительное».
 *
 * Включение, выключение и смена пароля сохраняются сразу; туннель поднят —
 * переподключение с новыми входами.
 */
class ShareScreen(host: Host) : SubScreen(host, R.string.share_title) {
    private val body = Ui.column(context, 12)
    private var settings: ShareSettings? = null
    private var failure: Diagnostic? = null
    private var busy = false
    private var watch: Job? = null
    private var pairing: Job? = null

    override fun content(): View = body

    override fun render(status: TunnelStatus) {
        body.removeAllViews()
        body.addView(
            Ui.text(context, R.style.Text_DPpass_Secondary, context.getString(R.string.share_intro)).apply {
                setPadding(Ui.dp(context, 4), 0, Ui.dp(context, 4), 0)
            },
        )
        failure?.let { d ->
            body.addView(
                Ui.card(context).apply {
                    addView(Ui.text(context, R.style.Text_DPpass_Secondary, d.message).apply { setTextColor(context.getColor(R.color.warning)) })
                },
                Ui.matchWidth(),
            )
        }
        val s = settings ?: return
        body.addView(
            Ui.listCard(context).apply {
                addView(
                    Ui.switchRow(
                        context,
                        R.drawable.ic_lan,
                        context.getString(R.string.share_enable),
                        context.getString(R.string.share_enable_note),
                        s.enabled,
                    ) { setSharing(it) },
                    Ui.matchWidth(),
                )
            },
            Ui.matchWidth(),
        )
        if (!s.enabled) return

        // ---- где подключаться ----
        body.addView(Ui.section(context, context.getString(R.string.share_where)))
        val endpoints = TunnelState.share.value
        when {
            !status.busy -> body.addView(note(R.string.share_needs_tunnel))
            endpoints.isEmpty() && status is TunnelStatus.Connected && TunnelState.shareRefused.value -> body.addView(note(R.string.share_refused))
            endpoints.isEmpty() && status is TunnelStatus.Connected -> body.addView(note(R.string.share_no_interfaces))
            endpoints.isEmpty() -> body.addView(note(R.string.share_waiting))
        }
        body.addView(
            Ui.listCard(context).apply {
                for (e in endpoints) {
                    val address = "${e.address}:${s.port}"
                    addView(
                        Ui.ListRow(context, R.drawable.ic_lan, address)
                            .subtitle(context.getString(R.string.share_address_note))
                            .trailing(
                                Ui.iconButton(context, R.drawable.ic_copy, context.getString(R.string.share_copy_address)) {
                                    copy(address, sensitive = false)
                                },
                            ),
                        Ui.matchWidth(),
                    )
                    addView(Ui.divider(context))
                }
                addView(
                    Ui.ListRow(context, R.drawable.ic_link, context.getString(R.string.share_link))
                        .subtitle(context.getString(R.string.share_link_note))
                        .onClick { shareLink(s, endpoints) },
                    Ui.matchWidth(),
                )
                addView(Ui.divider(context))
                addView(
                    Ui.ListRow(context, R.drawable.ic_open, context.getString(R.string.share_system))
                        .subtitle(context.getString(R.string.share_system_note))
                        .trailing(Ui.icon(context, R.drawable.ic_open, R.color.text_secondary))
                        .onClick { openSystem(Intent(Settings.ACTION_WIRELESS_SETTINGS)) },
                    Ui.matchWidth(),
                )
            },
            Ui.matchWidth(),
        )

        // ---- вход ----
        body.addView(Ui.section(context, context.getString(R.string.share_credentials)))
        body.addView(
            Ui.listCard(context).apply {
                addView(Ui.ListRow(context, R.drawable.ic_route, context.getString(R.string.share_port)).subtitle(s.port.toString()), Ui.matchWidth())
                addView(Ui.divider(context))
                addView(
                    Ui.ListRow(context, R.drawable.ic_key, context.getString(R.string.share_user))
                        .subtitle(s.user.reveal())
                        .trailing(
                            Ui.iconButton(context, R.drawable.ic_copy, context.getString(R.string.share_copy_user)) {
                                copy(s.user.reveal(), sensitive = true)
                            },
                        ),
                    Ui.matchWidth(),
                )
                addView(Ui.divider(context))
                addView(
                    Ui.ListRow(context, R.drawable.ic_key, context.getString(R.string.share_password))
                        .subtitle(s.password.reveal())
                        .trailing(
                            Ui.iconButton(context, R.drawable.ic_copy, context.getString(R.string.share_copy_password)) {
                                copy(s.password.reveal(), sensitive = true)
                            },
                        ),
                    Ui.matchWidth(),
                )
                addView(Ui.divider(context))
                addView(
                    Ui.ListRow(context, R.drawable.ic_refresh, context.getString(R.string.share_regenerate))
                        .subtitle(context.getString(R.string.share_regenerate_note))
                        .onClick { confirmRegenerate() },
                    Ui.matchWidth(),
                )
            },
            Ui.matchWidth(),
        )

        // ---- сопряжённые устройства (D-56) ----
        body.addView(Ui.section(context, context.getString(R.string.share_paired)))
        body.addView(
            Ui.listCard(context).apply {
                val dates = DateFormat.getMediumDateFormat(context)
                for (d in s.paired) {
                    addView(
                        Ui.ListRow(context, R.drawable.ic_lan, d.name)
                            .subtitle(context.getString(R.string.share_paired_note, dates.format(Date(d.pairedAtMillis))))
                            .trailing(Ui.iconButton(context, R.drawable.ic_delete, context.getString(R.string.share_unpair)) { confirmUnpair(d) }),
                        Ui.matchWidth(),
                    )
                    addView(Ui.divider(context))
                }
                addView(
                    Ui.ListRow(context, R.drawable.ic_add, context.getString(R.string.share_pair))
                        .subtitle(context.getString(R.string.share_pair_note))
                        .onClick { startPairing() },
                    Ui.matchWidth(),
                )
            },
            Ui.matchWidth(),
        )

        // ---- честные пределы (D-13) ----
        body.addView(Ui.section(context, context.getString(R.string.share_limits)))
        body.addView(
            Ui.card(context).apply {
                addView(Ui.text(context, R.style.Text_DPpass_Secondary, context.getString(R.string.share_limits_text)))
            },
            Ui.matchWidth(),
        )
    }

    /**
     * Сопряжение (D-56): порт сопряжения — на адресах раздачи, на две минуты,
     * одно соединение. Код — окном; вход только для этого устройства
     * выдаётся, когда код подтвердили на обоих телефонах.
     */
    private fun startPairing() {
        val core = host.graph?.core ?: return
        if (pairing?.isActive == true) return
        val endpoints = TetherInterfaces.find(context)
        if (endpoints.isEmpty()) {
            host.toast(context.getString(R.string.share_pair_no_tether))
            return
        }
        var waiting = true
        lateinit var sheet: Dialog
        val content = Ui.column(context, 12).apply {
            addView(Ui.text(context, R.style.Text_DPpass_Body, context.getString(R.string.share_pair_waiting)))
            addView(Ui.button(context, android.R.string.cancel, Ui.Style.OUTLINE).apply { setOnClickListener { sheet.dismiss() } }, Ui.matchWidth())
        }
        sheet = Ui.sheet(context, context.getString(R.string.share_pair), content)
        sheet.setOnDismissListener { if (waiting) pairing?.cancel() }
        sheet.show()
        val label = context.applicationInfo.loadLabel(context.packageManager).toString()
        pairing = host.scope.launch {
            val socket = withContext(Dispatchers.IO) { PairingLink.acceptOne(endpoints) }
            waiting = false
            sheet.dismiss()
            if (socket == null) {
                host.toast(context.getString(R.string.share_pair_timeout))
                return@launch
            }
            val r = try {
                socket.use { so ->
                    withContext(Dispatchers.IO) {
                        Pairing.host(
                            so.getInputStream(),
                            so.getOutputStream(),
                            SecureRandom(),
                            { code -> withContext(MainThread) { PairingDialog.ask(context, code) } },
                        ) {
                            val now = core.share.current().valueOrNull()
                            val name = context.getString(R.string.share_paired_default, (now?.paired?.size ?: 0) + 1)
                            core.share.pair(name, core.clock.nowMillis()).map { d ->
                                Pairing.Offer(now?.port ?: 0, d.user.reveal(), d.password.reveal(), label)
                            }
                        }
                    }
                }
            } catch (e: IOException) {
                Outcome.failure(Diagnostic.fromThrowable(DiagCode.PAIRING_BROKEN, "соединение сопряжения прервано", e))
            }
            when (r) {
                is Outcome.Failure -> {
                    r.errors.forEach(core.log::diagnostic)
                    host.problem(context.getString(R.string.share_pair), r.errors.first())
                }
                is Outcome.Success -> {
                    core.log.info("share_paired")
                    settings = core.share.current().valueOrNull() ?: settings
                    host.toast(context.getString(R.string.share_pair_done))
                    // Новый вход — во вход ядра: только новым запуском (D-51).
                    host.reconnectIfBusy()
                }
            }
            render(TunnelState.status.value)
        }
    }

    /** Отозвать доверие (D-56): вход этого устройства пропадает из ядра при переподключении. */
    private fun confirmUnpair(d: PairedDevice) {
        Ui.secure(
            AlertDialog.Builder(context)
                .setMessage(context.getString(R.string.share_unpair_confirm, d.name))
                .setPositiveButton(R.string.share_unpair) { _, _ -> change("share_unpaired") { it.unpair(d.id) } }
                .setNegativeButton(android.R.string.cancel, null)
                .show(),
        )
    }

    override fun onShown() {
        watch?.cancel()
        watch = host.scope.launch {
            if (settings == null) load()
            // Набор адресов раздачи и отказ раздачи меняет сервис туннеля: пока экран виден — перерисовка.
            combine(TunnelState.share, TunnelState.shareRefused) { _, _ -> }.collect { render(TunnelState.status.value) }
        }
    }

    override fun onHidden() {
        watch?.cancel()
        watch = null
    }

    private suspend fun load() {
        val core = host.graph?.core ?: return
        // Первое чтение — из зашифрованного хранилища (D-19): не на главном потоке.
        when (val r = withContext(Dispatchers.IO) { core.share.current() }) {
            is Outcome.Failure -> failure = r.errors.first()
            is Outcome.Success -> {
                settings = r.value
                failure = r.diagnostics.firstOrNull()
            }
        }
    }

    /**
     * Не `setEnabled`: переключатель зовёт его из лямбды внутри `apply` на
     * карточке, и там это имя — `View.setEnabled` карточки
     * (`ScreenNamesTest`).
     */
    private fun setSharing(on: Boolean) = change("share_switched", "enabled" to on) { it.setEnabled(on) }

    private fun confirmRegenerate() {
        Ui.secure(
            AlertDialog.Builder(context)
                .setMessage(context.getString(R.string.share_regenerate_confirm))
                .setPositiveButton(android.R.string.ok) { _, _ -> change("share_regenerated") { it.regenerate() } }
                .setNegativeButton(android.R.string.cancel, null)
                .show(),
        )
    }

    /**
     * Смена настроек раздачи: сохранить; не сохранилось — причина, прежнее
     * остаётся. Итог — в журнале ([event], без логина и пароля, D-11).
     */
    private fun change(event: String, vararg fields: Pair<String, Any?>, f: (ShareService) -> Outcome<ShareSettings>) {
        val core = host.graph?.core ?: return
        if (busy) return
        busy = true
        host.scope.launch {
            val r = try {
                withContext(Dispatchers.IO) { f(core.share) }
            } finally {
                busy = false
            }
            when (r) {
                is Outcome.Failure -> {
                    r.errors.forEach(core.log::diagnostic)
                    host.problem(context.getString(R.string.share_not_saved), r.errors.first())
                }
                is Outcome.Success -> {
                    settings = r.value
                    failure = null
                    core.log.info(event, *fields)
                    host.reconnectIfBusy()
                }
            }
            render(TunnelState.status.value)
        }
    }

    /**
     * «Поделиться входом» (D-55): ссылка `socks5://` для DPpass на другом
     * телефоне — он добавит этот телефон в устройства раздачи. В ссылке —
     * логин и пароль: уходит только в приложение, которое выбрал пользователь.
     */
    private fun shareLink(s: ShareSettings, endpoints: List<ShareSpec.Endpoint>) {
        val at = endpoints.firstOrNull()?.address
        if (at == null) {
            host.toast(context.getString(R.string.share_link_unavailable))
            return
        }
        val label = context.applicationInfo.loadLabel(context.packageManager).toString()
        val link = RelayLink(at, s.port, s.user.reveal(), s.password.reveal(), label).format()
        val send = Intent(Intent.ACTION_SEND).setType("text/plain").putExtra(Intent.EXTRA_TEXT, link)
        openSystem(Intent.createChooser(send, context.getString(R.string.share_link)))
    }

    private fun note(text: Int): View =
        Ui.text(context, R.style.Text_DPpass_Caption, context.getString(text)).apply { setPadding(Ui.dp(context, 4), 0, Ui.dp(context, 4), 0) }

    /** В буфер обмена ([Ui.copy]); Android 13+ сам показывает, что скопировано. */
    private fun copy(text: String, sensitive: Boolean) {
        val ok = Ui.copy(context, context.getString(R.string.share_title), text, sensitive)
        if (ok && Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU) host.toast(context.getString(R.string.share_copied))
    }

    private fun openSystem(intent: Intent) {
        try {
            context.startActivity(intent)
        } catch (e: ActivityNotFoundException) {
            host.toast(context.getString(R.string.no_system_screen))
        }
    }
}
