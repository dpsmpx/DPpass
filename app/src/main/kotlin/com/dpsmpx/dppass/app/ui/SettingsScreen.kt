package com.dpsmpx.dppass.app.ui

import android.app.UiModeManager
import android.content.ActivityNotFoundException
import android.content.Intent
import android.os.Build
import android.provider.Settings
import android.view.View
import com.dpsmpx.dppass.R
import com.dpsmpx.dppass.app.TunnelStatus
import com.dpsmpx.dppass.connection.ActivationResult
import com.dpsmpx.dppass.connection.AppMode
import com.dpsmpx.dppass.connection.DnsProvider
import com.dpsmpx.dppass.connection.PolicyService
import com.dpsmpx.dppass.connection.RoutingMode
import com.dpsmpx.dppass.connection.UserPolicy
import com.dpsmpx.dppass.diagnostics.Outcome
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * «Настройки» (D-38, D-40): политика пользователя — маршрутизация, DNS,
 * приложения; постоянный VPN и уведомления — в настройках Android;
 * автопереключение сервера (D-58); проверка сети (D-60);
 * раздача другим устройствам (D-51); тема; журнал (D-26) и «О программе»
 * (D-43).
 *
 * Смена политики — новая активация действующих серверов (D-07): при
 * отказе остаётся прежнее, и это видно. Туннель поднят — переподключение.
 */
class SettingsScreen(host: Host) : Screen(host) {
    private val body = Ui.column(context, 12)
    private var applying = false

    override val view: View = scroll(
        Ui.column(context, 12).apply {
            addView(header(context.getString(R.string.tab_settings)))
            addView(body, Ui.matchWidth())
        },
        topDp = 4,
    )

    override fun render(status: TunnelStatus) {
        val core = host.graph?.core
        val policy = core?.userPolicy?.currentOrDefault() ?: UserPolicy.DEFAULT
        val own = core?.activation?.state?.active?.source == PolicyService.OWN_DOCUMENT
        body.removeAllViews()

        // ---- маршрутизация ----
        body.addView(Ui.section(context, context.getString(R.string.settings_routing)))
        body.addView(
            Ui.segmented(
                context,
                listOf(context.getString(R.string.routing_all), context.getString(R.string.routing_ru_direct)),
                if (policy.mode == RoutingMode.RU_DIRECT) 1 else 0,
            ) { i -> change(policy.copy(mode = if (i == 1) RoutingMode.RU_DIRECT else RoutingMode.ALL_TUNNEL)) },
            Ui.matchWidth(),
        )
        body.addView(
            Ui.text(
                context,
                R.style.Text_DPpass_Caption,
                context.getString(if (policy.mode == RoutingMode.RU_DIRECT) R.string.routing_ru_direct_note else R.string.routing_all_note),
            ).apply { setPadding(Ui.dp(context, 4), 0, Ui.dp(context, 4), 0) },
        )
        if (own) {
            body.addView(
                Ui.text(context, R.style.Text_DPpass_Caption, context.getString(R.string.routing_own_document_note)).apply {
                    setTextColor(context.getColor(R.color.warning))
                    setPadding(Ui.dp(context, 4), 0, Ui.dp(context, 4), 0)
                },
            )
        }
        body.addView(
            Ui.listCard(context).apply {
                addView(
                    Ui.switchRow(context, R.drawable.ic_block, context.getString(R.string.settings_block_ads), context.getString(R.string.settings_block_ads_note), policy.blockAds) {
                        change(policy.copy(blockAds = it))
                    },
                    Ui.matchWidth(),
                )
                addView(Ui.divider(context))
                addView(
                    Ui.switchRow(context, R.drawable.ic_lan, context.getString(R.string.settings_bypass_lan), context.getString(R.string.settings_bypass_lan_note), policy.bypassLan) {
                        change(policy.copy(bypassLan = it))
                    },
                    Ui.matchWidth(),
                )
                addView(Ui.divider(context))
                addView(
                    Ui.ListRow(context, R.drawable.ic_apps, context.getString(R.string.settings_apps))
                        .subtitle(appsSummary(policy))
                        .trailing(Ui.icon(context, R.drawable.ic_chevron, R.color.text_secondary))
                        .onClick { host.push(AppsScreen(host) { change(it) }) },
                    Ui.matchWidth(),
                )
                addView(Ui.divider(context))
                addView(
                    Ui.ListRow(context, R.drawable.ic_search, context.getString(R.string.route_title))
                        .subtitle(context.getString(R.string.route_entry_note))
                        .trailing(Ui.icon(context, R.drawable.ic_chevron, R.color.text_secondary))
                        .onClick { host.push(RouteCheckScreen(host)) },
                    Ui.matchWidth(),
                )
            },
            Ui.matchWidth(),
        )

        // ---- DNS ----
        body.addView(Ui.section(context, context.getString(R.string.settings_dns)))
        body.addView(
            Ui.listCard(context).apply {
                DnsProvider.entries.forEachIndexed { i, p ->
                    if (i > 0) addView(Ui.divider(context))
                    addView(Ui.radioRow(context, dnsName(p), p.url, policy.dns == p) { change(policy.copy(dns = p)) }, Ui.matchWidth())
                }
            },
            Ui.matchWidth(),
        )
        body.addView(
            Ui.text(context, R.style.Text_DPpass_Caption, context.getString(R.string.settings_dns_note)).apply { setPadding(Ui.dp(context, 4), 0, Ui.dp(context, 4), 0) },
        )

        // ---- подключение ----
        body.addView(Ui.section(context, context.getString(R.string.settings_connection)))
        body.addView(
            Ui.listCard(context).apply {
                addView(
                    Ui.ListRow(context, R.drawable.ic_shield, context.getString(R.string.settings_always_on))
                        // В списке VPN Android приложение — под ярлыком установки: у личной сборки он случаен (D-47, D-49).
                        .subtitle(context.getString(R.string.settings_always_on_note, context.applicationInfo.loadLabel(context.packageManager)))
                        .trailing(Ui.icon(context, R.drawable.ic_open, R.color.text_secondary))
                        .onClick { openSystem(Intent(Settings.ACTION_VPN_SETTINGS)) },
                    Ui.matchWidth(),
                )
                addView(Ui.divider(context))
                addView(
                    // Согласие заранее заменять выбранный сервер, когда он перестал отвечать (D-58).
                    Ui.switchRow(context, R.drawable.ic_bolt, context.getString(R.string.settings_auto_switch), context.getString(R.string.settings_auto_switch_note), host.prefs.autoSwitch) {
                        host.prefs.autoSwitch = it
                        host.graph?.core?.log?.info("auto_switch", "on" to it)
                    },
                    Ui.matchWidth(),
                )
                addView(Ui.divider(context))
                addView(
                    Ui.ListRow(context, R.drawable.ic_bell, context.getString(R.string.settings_notifications))
                        .subtitle(context.getString(R.string.settings_notifications_note))
                        .trailing(Ui.icon(context, R.drawable.ic_open, R.color.text_secondary))
                        .onClick {
                            openSystem(Intent(Settings.ACTION_APP_NOTIFICATION_SETTINGS).putExtra(Settings.EXTRA_APP_PACKAGE, context.packageName))
                        },
                    Ui.matchWidth(),
                )
                addView(Ui.divider(context))
                addView(
                    Ui.ListRow(context, R.drawable.ic_lan, context.getString(R.string.share_title))
                        .subtitle(context.getString(R.string.settings_share_note))
                        .trailing(Ui.icon(context, R.drawable.ic_chevron, R.color.text_secondary))
                        .onClick { host.push(ShareScreen(host)) },
                    Ui.matchWidth(),
                )
            },
            Ui.matchWidth(),
        )

        // ---- оформление ----
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            val ui = context.getSystemService(UiModeManager::class.java)
            val current = when (ui.nightMode) {
                UiModeManager.MODE_NIGHT_NO -> 1
                UiModeManager.MODE_NIGHT_YES -> 2
                else -> 0
            }
            body.addView(Ui.section(context, context.getString(R.string.settings_theme)))
            body.addView(
                Ui.segmented(
                    context,
                    listOf(context.getString(R.string.theme_system), context.getString(R.string.theme_light), context.getString(R.string.theme_dark)),
                    current,
                ) { i ->
                    ui.setApplicationNightMode(
                        when (i) {
                            1 -> UiModeManager.MODE_NIGHT_NO
                            2 -> UiModeManager.MODE_NIGHT_YES
                            else -> UiModeManager.MODE_NIGHT_AUTO
                        },
                    )
                },
                Ui.matchWidth(),
            )
        }

        // ---- приложение ----
        body.addView(Ui.section(context, context.getString(R.string.settings_app)))
        body.addView(
            Ui.listCard(context).apply {
                addView(
                    Ui.ListRow(context, R.drawable.ic_log, context.getString(R.string.tab_log))
                        .subtitle(context.getString(R.string.settings_log_note))
                        .trailing(Ui.icon(context, R.drawable.ic_chevron, R.color.text_secondary))
                        .onClick { host.push(LogScreen(host)) },
                    Ui.matchWidth(),
                )
                addView(Ui.divider(context))
                addView(
                    Ui.ListRow(context, R.drawable.ic_speed, context.getString(R.string.netcheck_title))
                        .subtitle(context.getString(R.string.netcheck_settings_note))
                        .trailing(Ui.icon(context, R.drawable.ic_chevron, R.color.text_secondary))
                        .onClick { host.push(NetworkCheckScreen(host)) },
                    Ui.matchWidth(),
                )
                addView(Ui.divider(context))
                addView(
                    Ui.ListRow(context, R.drawable.ic_info, context.getString(R.string.about_title))
                        .subtitle(host.graph?.appVersion)
                        .trailing(Ui.icon(context, R.drawable.ic_chevron, R.color.text_secondary))
                        .onClick { host.push(AboutScreen(host)) },
                    Ui.matchWidth(),
                )
            },
            Ui.matchWidth(),
        )
    }

    private fun appsSummary(p: UserPolicy): String = when (p.appMode) {
        AppMode.ALL -> context.getString(R.string.apps_all)
        AppMode.EXCEPT -> context.resources.getQuantityString(R.plurals.apps_except, p.apps.size, p.apps.size)
        AppMode.ONLY -> context.resources.getQuantityString(R.plurals.apps_only, p.apps.size, p.apps.size)
    }

    private fun dnsName(p: DnsProvider): String = when (p) {
        DnsProvider.CLOUDFLARE -> "Cloudflare"
        DnsProvider.GOOGLE -> "Google"
        DnsProvider.QUAD9 -> "Quad9"
    }

    /** Смена политики (D-38): активация с новой политикой; отказ — с причиной, прежнее остаётся. */
    private fun change(next: UserPolicy) {
        val core = host.graph?.core ?: return
        if (applying || next == core.userPolicy.currentOrDefault()) return
        applying = true
        host.scope.launch {
            val r = try {
                withContext(Dispatchers.IO) { core.userPolicy.change(next) }
            } finally {
                applying = false
            }
            when (r) {
                is Outcome.Failure -> host.problem(context.getString(R.string.settings_not_applied), r.errors.first())
                is Outcome.Success -> when (val a = r.value) {
                    is ActivationResult.Rejected -> a.diagnostics.firstOrNull { it.isError }?.let { host.problem(context.getString(R.string.settings_not_applied), it) }
                    is ActivationResult.Activated -> host.reconnectIfBusy()
                    null -> Unit
                }
            }
            host.changed()
        }
    }

    private fun openSystem(intent: Intent) {
        try {
            context.startActivity(intent)
        } catch (e: ActivityNotFoundException) {
            host.toast(context.getString(R.string.no_system_screen))
        }
    }
}
