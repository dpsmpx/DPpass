package com.dpsmpx.dppass.app.ui

import android.app.AlertDialog
import android.os.Build
import android.view.View
import com.dpsmpx.dppass.R
import com.dpsmpx.dppass.app.TunnelStatus
import com.dpsmpx.dppass.connection.LocalProxyService
import com.dpsmpx.dppass.connection.LocalProxySettings
import com.dpsmpx.dppass.diagnostics.Diagnostic
import com.dpsmpx.dppass.diagnostics.Outcome
import com.dpsmpx.dppass.engine.LocalProxySpec
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * «Подключение без VPN» (D-95): вместо VPN DPpass открывает на телефоне
 * прокси SOCKS5/HTTP с логином и паролем на 127.0.0.1 — через сервер идут
 * только приложения, где он указан. Здесь — переключатель, адрес, порт,
 * логин и пароль с копированием и смена порта и пароля. Логин и пароль
 * видны только на этом экране (`FLAG_SECURE`, T9), в буфер уходят с
 * пометкой «чувствительное». Смена при поднятом подключении — переподключение.
 */
class LocalProxyScreen(host: Host) : SubScreen(host, R.string.local_proxy_title) {
    private val body = Ui.column(context, 12)
    private var settings: LocalProxySettings? = null
    private var failure: Diagnostic? = null
    private var busy = false

    override fun content(): View = body

    override fun onShown() {
        if (settings == null && failure == null) host.scope.launch { load() }
    }

    override fun render(status: TunnelStatus) {
        body.removeAllViews()
        failure?.let {
            body.addView(
                Ui.text(context, R.style.Text_DPpass_Secondary, context.getString(R.string.error_with_reason, context.getString(Ui.kind(it.kind)), it.message))
                    .apply { setTextColor(context.getColor(R.color.error)) },
            )
        }
        val s = settings ?: return
        body.addView(
            Ui.listCard(context).apply {
                addView(
                    Ui.switchRow(
                        context,
                        R.drawable.ic_route,
                        context.getString(R.string.local_proxy_switch),
                        context.getString(R.string.local_proxy_switch_note),
                        s.enabled,
                    ) { on -> change("local_proxy_switched", "enabled" to on) { it.setEnabled(on) } },
                    Ui.matchWidth(),
                )
            },
            Ui.matchWidth(),
        )
        body.addView(note(R.string.local_proxy_note))

        body.addView(Ui.section(context, context.getString(R.string.local_proxy_credentials)))
        body.addView(
            Ui.listCard(context).apply {
                val address = Ui.ListRow(context, R.drawable.ic_route, context.getString(R.string.local_proxy_address)).subtitle(LocalProxySpec.ADDRESS)
                addView(address, Ui.matchWidth())
                addView(Ui.divider(context))
                addView(Ui.ListRow(context, R.drawable.ic_route, context.getString(R.string.share_port)).subtitle(s.port.toString()), Ui.matchWidth())
                addView(Ui.divider(context))
                addView(secretRow(R.string.share_user, R.string.share_copy_user, s.user.reveal()), Ui.matchWidth())
                addView(Ui.divider(context))
                addView(secretRow(R.string.share_password, R.string.share_copy_password, s.password.reveal()), Ui.matchWidth())
                addView(Ui.divider(context))
                addView(
                    Ui.ListRow(context, R.drawable.ic_copy, context.getString(R.string.local_proxy_copy_link))
                        .subtitle(context.getString(R.string.local_proxy_copy_link_note))
                        .onClick { copy(s.link()) },
                    Ui.matchWidth(),
                )
                addView(Ui.divider(context))
                addView(
                    Ui.ListRow(context, R.drawable.ic_refresh, context.getString(R.string.local_proxy_regenerate))
                        .subtitle(context.getString(R.string.local_proxy_regenerate_note))
                        .onClick { confirmRegenerate() },
                    Ui.matchWidth(),
                )
            },
            Ui.matchWidth(),
        )
    }

    private fun secretRow(title: Int, copyLabel: Int, value: String): View =
        Ui.ListRow(context, R.drawable.ic_key, context.getString(title))
            .subtitle(value)
            .trailing(Ui.iconButton(context, R.drawable.ic_copy, context.getString(copyLabel)) { copy(value) })

    private suspend fun load() {
        val core = host.graph?.core ?: return
        // Первое чтение — из зашифрованного хранилища (D-19): не на главном потоке.
        when (val r = withContext(Dispatchers.IO) { core.localProxy.current() }) {
            is Outcome.Failure -> failure = r.errors.first()
            is Outcome.Success -> {
                settings = r.value
                failure = r.diagnostics.firstOrNull()
            }
        }
        host.changed()
    }

    private fun confirmRegenerate() {
        Ui.secure(
            AlertDialog.Builder(context)
                .setMessage(context.getString(R.string.local_proxy_regenerate_confirm))
                .setPositiveButton(android.R.string.ok) { _, _ -> change("local_proxy_regenerated") { it.regenerate() } }
                .setNegativeButton(android.R.string.cancel, null)
                .show(),
        )
    }

    /**
     * Смена настроек: сохранить; не сохранилось — причина, прежнее остаётся.
     * Итог — в журнале ([event], без логина и пароля, D-11); подключение
     * поднято — переподключение с новым входом или через VPN.
     */
    private fun change(event: String, vararg fields: Pair<String, Any?>, f: (LocalProxyService) -> Outcome<LocalProxySettings>) {
        val core = host.graph?.core ?: return
        if (busy) return
        busy = true
        host.scope.launch {
            val r = try {
                withContext(Dispatchers.IO) { f(core.localProxy) }
            } finally {
                busy = false
            }
            when (r) {
                is Outcome.Failure -> {
                    r.errors.forEach(core.log::diagnostic)
                    host.problem(context.getString(R.string.local_proxy_not_saved), r.errors.first())
                }
                is Outcome.Success -> {
                    settings = r.value
                    failure = null
                    core.log.info(event, *fields)
                    host.reconnectIfBusy()
                }
            }
            host.changed()
        }
    }

    private fun note(text: Int): View =
        Ui.text(context, R.style.Text_DPpass_Caption, context.getString(text)).apply { setPadding(Ui.dp(context, 4), 0, Ui.dp(context, 4), 0) }

    private fun copy(text: String) {
        val ok = Ui.copy(context, context.getString(R.string.local_proxy_title), text, sensitive = true)
        if (ok && Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU) host.toast(context.getString(R.string.share_copied))
    }
}
