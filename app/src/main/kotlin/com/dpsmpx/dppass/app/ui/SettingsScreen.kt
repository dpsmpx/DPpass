package com.dpsmpx.dppass.app.ui

import android.app.AlertDialog
import android.app.UiModeManager
import android.content.ActivityNotFoundException
import android.content.Intent
import android.os.Build
import android.provider.Settings
import android.text.InputType
import android.view.Gravity
import android.view.View
import com.dpsmpx.dppass.R
import com.dpsmpx.dppass.app.TunnelStatus
import com.dpsmpx.dppass.connection.ActivationResult
import com.dpsmpx.dppass.connection.AppMode
import com.dpsmpx.dppass.connection.DnsProvider
import com.dpsmpx.dppass.connection.PolicyService
import com.dpsmpx.dppass.connection.RoutingMode
import com.dpsmpx.dppass.connection.ServerlessSettings
import com.dpsmpx.dppass.connection.UserPolicy
import com.dpsmpx.dppass.diagnostics.Outcome
import com.dpsmpx.dppass.diagnostics.Safe
import com.dpsmpx.dppass.network.NetworkChangeChecks
import com.dpsmpx.dppass.routing.SplitSites
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * «Настройки» (D-38, D-40): политика пользователя — маршрутизация, DNS,
 * приложения; постоянный VPN и уведомления — в настройках Android;
 * автопереключение сервера (D-58); проверка сети (D-60); напоминание о
 * конце подписки (D-76);
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
        // Привязанные маршрутизация и DNS поставщика (D-98): режим, реклама и DNS здесь ждут отвязки — не молча.
        core?.providerPolicyInEffect()?.let { bound ->
            body.addView(
                Ui.text(context, R.style.Text_DPpass_Caption, context.getString(R.string.routing_provider_note, bound.subscription.displayName)).apply {
                    setTextColor(context.getColor(R.color.warning))
                    setPadding(Ui.dp(context, 4), 0, Ui.dp(context, 4), 0)
                },
            )
        }
        body.addView(
            Ui.listCard(context).apply {
                addView(
                    Ui.switchRow(
                        context,
                        R.drawable.ic_block,
                        context.getString(R.string.settings_block_ads),
                        context.getString(R.string.settings_block_ads_note),
                        policy.blockAds,
                    ) {
                        change(policy.copy(blockAds = it))
                    },
                    Ui.matchWidth(),
                )
                addView(Ui.divider(context))
                addView(
                    Ui.switchRow(
                        context,
                        R.drawable.ic_lan,
                        context.getString(R.string.settings_bypass_lan),
                        context.getString(R.string.settings_bypass_lan_note),
                        policy.bypassLan,
                    ) {
                        change(policy.copy(bypassLan = it))
                    },
                    Ui.matchWidth(),
                )
                addView(Ui.divider(context))
                // Свои списки сайтов (D-93): раньше правил режима.
                addView(
                    Ui.ListRow(context, R.drawable.ic_route, context.getString(R.string.site_lists_title))
                        .subtitle(SiteListsScreen.summary(host, policy))
                        .trailing(Ui.icon(context, R.drawable.ic_chevron, R.color.text_secondary))
                        .onClick { host.push(SiteListsScreen(host)) },
                    Ui.matchWidth(),
                )
                addView(Ui.divider(context))
                addView(
                    Ui.ListRow(context, R.drawable.ic_apps, context.getString(R.string.settings_apps))
                        .subtitle(appsSummary(policy))
                        .trailing(Ui.icon(context, R.drawable.ic_chevron, R.color.text_secondary))
                        .onClick {
                            host.push(
                                AppsScreen(host, R.string.settings_apps, policy.appMode, policy.apps) { mode, apps ->
                                    val base = host.graph?.core?.userPolicy?.currentOrDefault() ?: UserPolicy.DEFAULT
                                    change(base.copy(appMode = mode, apps = apps))
                                },
                            )
                        },
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
            Ui.text(context, R.style.Text_DPpass_Caption, context.getString(R.string.settings_dns_note)).apply {
                setPadding(Ui.dp(context, 4), 0, Ui.dp(context, 4), 0)
            },
        )

        // ---- подключение ----
        body.addView(Ui.section(context, context.getString(R.string.settings_connection)))
        body.addView(
            Ui.listCard(context).apply {
                // Подключение без VPN (D-95): локальный прокси с паролем вместо VPN.
                val local = host.graph?.core?.localProxy?.current()?.valueOrNull()
                addView(
                    Ui.ListRow(context, R.drawable.ic_route, context.getString(R.string.local_proxy_title))
                        .subtitle(
                            if (local?.enabled == true) {
                                context.getString(R.string.local_proxy_row_on, local.port)
                            } else {
                                context.getString(R.string.local_proxy_off)
                            },
                        )
                        .trailing(Ui.icon(context, R.drawable.ic_chevron, R.color.text_secondary))
                        .onClick { host.push(LocalProxyScreen(host)) },
                    Ui.matchWidth(),
                )
                addView(Ui.divider(context))
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
                    Ui.switchRow(
                        context,
                        R.drawable.ic_bolt,
                        context.getString(R.string.settings_auto_switch),
                        context.getString(R.string.settings_auto_switch_note),
                        host.prefs.autoSwitch,
                    ) {
                        host.prefs.autoSwitch = it
                        host.graph?.core?.log?.info("auto_switch", "on" to it)
                    },
                    Ui.matchWidth(),
                )
                addView(Ui.divider(context))
                addView(
                    // Проверка новой сети при поднятом туннеле (D-67): выключено — только по кнопке (D-60).
                    Ui.switchRow(
                        context,
                        R.drawable.ic_speed,
                        context.getString(R.string.settings_check_on_change),
                        context.resources.getQuantityString(
                            R.plurals.settings_check_on_change_note,
                            NetworkChangeChecks.MAX_PER_HOUR,
                            (NetworkChangeChecks.SETTLE_MILLIS / 1000).toInt(),
                            NetworkChangeChecks.MAX_PER_HOUR,
                        ),
                        host.prefs.checkOnNetworkChange,
                    ) {
                        host.prefs.checkOnNetworkChange = it
                        host.graph?.core?.log?.info("check_on_network_change", "on" to it)
                    },
                    Ui.matchWidth(),
                )
                addView(Ui.divider(context))
                addView(
                    // Разбиение ClientHello к серверу (D-68): действует сразу — туннель переподключается.
                    Ui.switchRow(
                        context,
                        R.drawable.ic_shield,
                        context.getString(R.string.settings_split_hello),
                        context.getString(R.string.settings_split_hello_note),
                        host.prefs.splitClientHello,
                    ) {
                        host.prefs.splitClientHello = it
                        host.graph?.core?.log?.info("client_hello_split_set", "on" to it)
                        host.reconnectIfBusy()
                    },
                    Ui.matchWidth(),
                )
                addView(Ui.divider(context))
                // Сайты напрямую с разбиением (D-72): список телефона; действует сразу.
                val sitesRow = Ui.ListRow(context, R.drawable.ic_shield, context.getString(R.string.settings_split_sites))
                    .subtitle(splitSitesSummary(host.prefs.splitSites()))
                    .trailing(Ui.icon(context, R.drawable.ic_open, R.color.text_secondary))
                sitesRow.onClick { editSplitSites(sitesRow) }
                addView(sitesRow, Ui.matchWidth())
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

        // ---- без сервера (D-73) ----
        body.addView(Ui.section(context, context.getString(R.string.settings_serverless)))
        val serverless = host.prefs.serverless
        body.addView(
            Ui.listCard(context).apply {
                addView(
                    choiceRow(
                        R.drawable.ic_route,
                        R.string.serverless_rest,
                        listOf(R.string.serverless_rest_direct, R.string.serverless_rest_split),
                        serverless.rest.ordinal,
                    ) { i -> setServerless(host.prefs.serverless.copy(rest = ServerlessSettings.Rest.entries[i])) },
                    Ui.matchWidth(),
                )
                addView(Ui.divider(context))
                addView(
                    choiceRow(
                        R.drawable.ic_dns,
                        R.string.serverless_dns,
                        listOf(R.string.serverless_dns_doh, R.string.serverless_dns_system),
                        serverless.dns.ordinal,
                    ) { i -> setServerless(host.prefs.serverless.copy(dns = ServerlessSettings.Dns.entries[i])) },
                    Ui.matchWidth(),
                )
                addView(Ui.divider(context))
                addView(
                    choiceRow(
                        R.drawable.ic_apps,
                        R.string.serverless_apps,
                        listOf(R.string.serverless_apps_same, R.string.serverless_apps_own, R.string.serverless_apps_all),
                        serverless.apps.ordinal,
                        subtitle = serverlessAppsSummary(serverless, policy),
                    ) { i ->
                        val apps = ServerlessSettings.Apps.entries[i]
                        if (apps == ServerlessSettings.Apps.OWN) {
                            // Свой выбор — тем же экраном, что с сервером; сохраняется кнопкой «Готово».
                            val now = host.prefs.serverless
                            host.push(
                                AppsScreen(host, R.string.serverless_apps, now.ownMode, now.ownApps) { mode, packages ->
                                    setServerless(host.prefs.serverless.copy(apps = apps, ownMode = mode, ownApps = packages))
                                },
                            )
                        } else {
                            setServerless(host.prefs.serverless.copy(apps = apps))
                        }
                    },
                    Ui.matchWidth(),
                )
            },
            Ui.matchWidth(),
        )
        body.addView(
            Ui.text(context, R.style.Text_DPpass_Caption, context.getString(R.string.settings_serverless_note)).apply {
                setPadding(Ui.dp(context, 4), 0, Ui.dp(context, 4), 0)
            },
        )

        // ---- подписки: напоминание о конце (D-76) ----
        body.addView(Ui.section(context, context.getString(R.string.tab_subscriptions)))
        body.addView(
            Ui.listCard(context).apply {
                addView(
                    Ui.ListRow(context, R.drawable.ic_clock, context.getString(R.string.expiry_settings_title))
                        .subtitle(ExpiryReminderScreen.summary(context, host.prefs.expiryReminders))
                        .trailing(Ui.icon(context, R.drawable.ic_chevron, R.color.text_secondary))
                        .onClick { host.push(ExpiryReminderScreen(host)) },
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
                    Ui.ListRow(context, R.drawable.ic_file, context.getString(R.string.export_title))
                        .subtitle(context.getString(R.string.export_settings_note))
                        .trailing(Ui.icon(context, R.drawable.ic_chevron, R.color.text_secondary))
                        .onClick { ExportFlow.menu(host) },
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
                    is ActivationResult.Rejected -> a.diagnostics.firstOrNull { it.isError }?.let {
                        host.problem(context.getString(R.string.settings_not_applied), it)
                    }
                    is ActivationResult.Activated -> host.reconnectIfBusy()
                    null -> Unit
                }
            }
            host.changed()
        }
    }

    /** Строка выбора: подпись — выбранный вариант (или [subtitle]); нажатие — окно с вариантами. */
    private fun choiceRow(icon: Int, title: Int, options: List<Int>, selected: Int, subtitle: String? = null, pick: (Int) -> Unit): Ui.ListRow =
        Ui.ListRow(context, icon, context.getString(title))
            .subtitle(subtitle ?: context.getString(options[selected]))
            .trailing(Ui.icon(context, R.drawable.ic_chevron, R.color.text_secondary))
            .onClick {
                AlertDialog.Builder(context)
                    .setTitle(title)
                    .setSingleChoiceItems(options.map(context::getString).toTypedArray(), selected) { d, which ->
                        d.dismiss()
                        pick(which)
                    }
                    .setNegativeButton(android.R.string.cancel, null)
                    .show()
            }

    private fun serverlessAppsSummary(s: ServerlessSettings, policy: UserPolicy): String = when (s.apps) {
        ServerlessSettings.Apps.SAME -> context.getString(R.string.serverless_apps_same_summary, appsSummary(policy))
        ServerlessSettings.Apps.OWN -> context.getString(R.string.serverless_apps_own_summary, appsSummary(policy.copy(appMode = s.ownMode, apps = s.ownApps)))
        ServerlessSettings.Apps.ALL -> context.getString(R.string.serverless_apps_all)
    }

    /**
     * Выбор без сервера (D-73) — настройка телефона. Туннель без сервера
     * (серверов нет) переподключается сразу; с серверами выбор подождёт.
     */
    private fun setServerless(next: ServerlessSettings) {
        if (next == host.prefs.serverless) return
        host.prefs.serverless = next
        val core = host.graph?.core
        core?.log?.info("serverless_set", "rest" to Safe(next.rest.wire), "dns" to Safe(next.dns.wire), "apps" to Safe(next.apps.wire))
        if (core?.activation?.state?.activeConfig == null) host.reconnectIfBusy()
        host.changed()
    }

    private fun splitSitesSummary(sites: SplitSites): String =
        if (sites.isEmpty) {
            context.getString(R.string.settings_split_sites_empty)
        } else {
            context.resources.getQuantityString(R.plurals.settings_split_sites_count, sites.size, sites.size)
        }

    /**
     * Правка списка «Напрямую с разбиением» (D-72): запись на строку. Неверная
     * строка или код geosite, которого нет в наборе (D-27), — ошибка у поля,
     * окно не закрывается; сохраняется только разобранный список.
     */
    private fun editSplitSites(row: Ui.ListRow) {
        val field = Ui.field(
            context,
            R.string.split_sites_hint,
            InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_FLAG_MULTI_LINE or InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS,
        ).apply {
            isSingleLine = false
            minLines = 4
            maxLines = 10
            gravity = Gravity.TOP or Gravity.START
            val p = Ui.dp(context, 12)
            setPadding(Ui.dp(context, 16), p, Ui.dp(context, 16), p)
            setText(host.prefs.splitSitesText)
        }
        val form = Ui.column(context, 8).apply {
            val p = Ui.dp(context, 24)
            setPadding(p, Ui.dp(context, 8), p, 0)
            addView(Ui.text(context, R.style.Text_DPpass_Secondary, context.getString(R.string.split_sites_note)), Ui.matchWidth())
            addView(field, Ui.matchWidth())
        }
        val dialog = AlertDialog.Builder(context)
            .setTitle(R.string.settings_split_sites)
            .setView(form)
            .setPositiveButton(R.string.action_save, null)
            .setNegativeButton(android.R.string.cancel, null)
            .show()
        Ui.secure(dialog)
        dialog.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener {
            val parsed = SplitSites.parse(field.text.toString())
            val sites = parsed.valueOrNull()
            val problem = (parsed as? Outcome.Failure)?.errors?.first()
                ?: sites?.let { host.graph?.core?.checkSplitSites(it)?.firstOrNull { d -> d.isError } }
            if (problem != null || sites == null) {
                field.error = problem?.message
                return@setOnClickListener
            }
            host.prefs.splitSitesText = sites.format()
            host.graph?.core?.log?.info("split_sites_set", "n" to sites.size)
            row.subtitle(splitSitesSummary(sites))
            dialog.dismiss()
            host.reconnectIfBusy()
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
