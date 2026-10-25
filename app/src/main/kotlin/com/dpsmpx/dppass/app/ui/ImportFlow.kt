package com.dpsmpx.dppass.app.ui

import android.app.AlertDialog
import android.app.Dialog
import android.content.ClipboardManager
import android.content.pm.PackageManager
import android.text.InputType
import com.dpsmpx.dppass.R
import com.dpsmpx.dppass.app.TunnelState
import com.dpsmpx.dppass.app.TunnelStatus
import com.dpsmpx.dppass.connection.ActivationResult
import com.dpsmpx.dppass.connection.ImportClassifier
import com.dpsmpx.dppass.connection.ImportKind
import com.dpsmpx.dppass.connection.RelayLink
import com.dpsmpx.dppass.core.SubscriptionId
import com.dpsmpx.dppass.diagnostics.DiagCode
import com.dpsmpx.dppass.diagnostics.Diagnostic
import com.dpsmpx.dppass.diagnostics.Outcome
import com.dpsmpx.dppass.subscriptions.UpdateResult
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * Импорт (D-42): меню «Добавить», буфер обмена, файл, «Поделиться»,
 * адрес подписки и QR с картинки (D-65). Принесённое распознаётся (`ImportClassifier`), и
 * пользователь видит сводку — ничего не применяется без его нажатия
 * (T13: «Поделиться» — данные чужого приложения).
 */
internal object ImportFlow {
    /** Подписки, которые сейчас загружаются: их кнопки выключены на всех экранах. */
    val running: MutableSet<SubscriptionId> = HashSet()

    fun menu(host: Host) {
        val c = host.activity
        val items = Ui.listCard(c)
        lateinit var sheet: Dialog
        fun item(icon: Int, title: Int, subtitle: Int, action: () -> Unit) {
            if (items.childCount > 0) items.addView(Ui.divider(c))
            items.addView(Ui.ListRow(c, icon, c.getString(title)).subtitle(c.getString(subtitle)).onClick { sheet.dismiss(); action() }, Ui.matchWidth())
        }
        item(R.drawable.ic_link, R.string.subs_add, R.string.add_subscription_note) { addSubscription(host) }
        item(R.drawable.ic_paste, R.string.import_clipboard, R.string.add_clipboard_note) { fromClipboard(host) }
        item(R.drawable.ic_file, R.string.import_file, R.string.add_file_note) { host.pickFile() }
        // Без камеры пункта нет (D-71): «QR-код с картинки» работает и так.
        if (c.packageManager.hasSystemFeature(PackageManager.FEATURE_CAMERA_ANY)) {
            item(R.drawable.ic_qr, R.string.import_qr_camera, R.string.add_qr_camera_note) { host.scanQr() }
        }
        item(R.drawable.ic_qr, R.string.import_qr, R.string.add_qr_note) { host.pickQrImage() }
        item(R.drawable.ic_lan, R.string.relays_entry, R.string.relays_entry_note) { host.push(RelaysScreen(host)) }
        sheet = Ui.sheet(c, c.getString(R.string.add_title), items)
        sheet.show()
    }

    fun fromClipboard(host: Host) {
        val c = host.activity
        val clip = c.getSystemService(ClipboardManager::class.java).primaryClip
        val text = clip?.takeIf { it.itemCount > 0 }?.getItemAt(0)?.coerceToText(c)?.toString()
        if (text.isNullOrBlank()) {
            host.toast(c.getString(R.string.clipboard_empty))
            return
        }
        handle(host, text)
    }

    /** Распознать и спросить. */
    fun handle(host: Host, text: String) {
        val c = host.activity
        if (host.graph == null) {
            host.toast(c.getString(R.string.not_ready))
            return
        }
        host.scope.launch {
            when (val kind = withContext(Dispatchers.Default) { ImportClassifier.classify(text) }) {
                ImportKind.Empty -> host.toast(c.getString(R.string.clipboard_empty))
                ImportKind.OwnDocument -> confirmDocument(host, text)
                is ImportKind.SubscriptionUrl -> addSubscription(host, kind.url)
                is ImportKind.Links -> confirmLinks(host, text, kind)
                is ImportKind.Relay -> confirmRelay(host, kind.link)
                is ImportKind.HappRouting -> confirmHapp(host, kind.text)
                is ImportKind.Unrecognized -> host.problem(
                    c.getString(R.string.import_unrecognized),
                    kind.reason ?: Diagnostic.error(DiagCode.SUBSCRIPTION_FORMAT_UNKNOWN, c.getString(R.string.import_unrecognized_text)),
                )
            }
        }
    }

    private fun confirmDocument(host: Host, text: String) {
        val c = host.activity
        Ui.secure(
            AlertDialog.Builder(c)
                .setTitle(R.string.import_document_title)
                .setMessage(R.string.import_document_text)
                .setPositiveButton(R.string.action_apply) { _, _ ->
                    val graph = host.graph ?: return@setPositiveButton
                    host.scope.launch {
                        val r = withContext(Dispatchers.IO) { graph.core.importAndActivate(text) }
                        val failure: Diagnostic? = when (r) {
                            is Outcome.Failure -> r.errors.first()
                            is Outcome.Success -> (r.value as? ActivationResult.Rejected)?.diagnostics?.firstOrNull { it.isError }
                        }
                        if (failure == null) {
                            host.toast(c.getString(R.string.import_done))
                            host.reconnectIfBusy()
                        } else {
                            host.problem(c.getString(R.string.import_failed, c.getString(Ui.kind(failure.kind))), failure)
                        }
                        host.changed()
                    }
                }
                .setNegativeButton(android.R.string.cancel, null)
                .show(),
        )
    }

    /**
     * Вход раздачи другого телефона (D-55): добавить в доверенные устройства —
     * только с согласия, имя можно сменить. Адрес — шлюз сети: подсеть
     * раздачи Android меняет, адрес из ссылки устареет.
     */
    private fun confirmRelay(host: Host, link: RelayLink) {
        val c = host.activity
        val name = Ui.field(c, R.string.relays_name_hint).apply { setText(link.draft(c.getString(R.string.relays_default_name)).name) }
        lateinit var sheet: Dialog
        val body = Ui.column(c, 12).apply {
            addView(Ui.text(c, R.style.Text_DPpass_Body, c.getString(R.string.relays_link_text, link.port)))
            addView(name, Ui.matchWidth())
            addView(
                Ui.button(c, R.string.action_save, Ui.Style.PRIMARY, R.drawable.ic_check).apply {
                    setOnClickListener {
                        val core = host.graph?.core ?: return@setOnClickListener
                        when (val r = core.relays.add(link.draft("").copy(name = name.text.toString()))) {
                            is Outcome.Failure -> host.problem(c.getString(Ui.kind(r.errors.first().kind)), r.errors.first())
                            is Outcome.Success -> {
                                sheet.dismiss()
                                host.toast(c.getString(R.string.relays_added))
                                host.push(RelaysScreen(host))
                            }
                        }
                    }
                },
                Ui.matchWidth(),
            )
        }
        sheet = Ui.sheet(c, c.getString(R.string.relays_add_title), body)
        sheet.show()
    }

    /**
     * Профиль маршрутизации Happ (D-93): что добавится в свои списки и что
     * не будет взято — с причинами; добавляется только по нажатию (T13).
     */
    private fun confirmHapp(host: Host, text: String) {
        val c = host.activity
        val core = host.graph?.core ?: return
        host.scope.launch {
            val parsed = withContext(Dispatchers.Default) { core.parseHappRouting(text) }
            val r = when (parsed) {
                is Outcome.Failure -> return@launch host.problem(c.getString(R.string.import_happ_title), parsed.errors.first())
                is Outcome.Success -> parsed.value
            }
            lateinit var sheet: Dialog
            val body = Ui.column(c, 12).apply {
                val summary = c.getString(R.string.import_happ_summary, r.lists.direct.size, r.lists.proxy.size, r.lists.block.size)
                addView(Ui.text(c, R.style.Text_DPpass_Body, summary))
                if (r.skipped.isNotEmpty()) {
                    val shown = r.skipped.take(SKIPPED_SHOWN).joinToString("\n") { "• ${it.field}: ${it.reason}" }
                    val rest = r.skipped.size - SKIPPED_SHOWN
                    val more = if (rest > 0) "\n" + c.resources.getQuantityString(R.plurals.import_happ_more, rest, rest) else ""
                    addView(Ui.text(c, R.style.Text_DPpass_Secondary, c.getString(R.string.import_happ_skipped)))
                    addView(Ui.text(c, R.style.Text_DPpass_Caption, shown + more).apply { setTextIsSelectable(true) })
                }
                addView(Ui.text(c, R.style.Text_DPpass_Caption, c.getString(R.string.import_happ_note)))
                addView(
                    Ui.button(c, R.string.import_happ_add, Ui.Style.PRIMARY, R.drawable.ic_check).apply {
                        setOnClickListener {
                            sheet.dismiss()
                            host.scope.launch {
                                val done = withContext(Dispatchers.IO) { core.userPolicy.addSiteLists(r.lists) }
                                SiteListsScreen.applied(host, done, R.string.import_happ_done)
                            }
                        }
                    },
                    Ui.matchWidth(),
                )
            }
            val title = r.name?.let { c.getString(R.string.import_happ_named, it) } ?: c.getString(R.string.import_happ_title)
            sheet = Ui.sheet(c, title, body)
            sheet.show()
        }
    }

    private fun confirmLinks(host: Host, text: String, kind: ImportKind.Links) {
        val c = host.activity
        if (kind.usable == 0) {
            val first = kind.problems.firstOrNull()
                ?: Diagnostic.error(DiagCode.SUBSCRIPTION_NO_USABLE_SERVERS, c.getString(R.string.import_no_usable))
            host.problem(c.getString(R.string.import_no_usable), first)
            return
        }
        val name = Ui.field(c, R.string.subs_name_hint).apply { setText(R.string.own_servers_default_name) }
        lateinit var sheet: Dialog
        val body = Ui.column(c, 12).apply {
            addView(Ui.text(c, R.style.Text_DPpass_Body, c.resources.getQuantityString(R.plurals.import_links_summary, kind.total, kind.usable, kind.total)))
            if (kind.usable < kind.total) {
                // Причины пропуска — по коду, без значений из ссылок (D-22). Они в глубине
                // цепочки: запись → ссылка → схема или параметр (D-90: тест пути нашёл).
                fun chain(d: Diagnostic): List<Diagnostic> = listOf(d) + d.causes.flatMap(::chain)
                val reasons = kind.problems.flatMap(::chain)
                    .filter { it.code == DiagCode.SHARE_LINK_PARAM_UNSUPPORTED || it.code == DiagCode.SHARE_LINK_SCHEME_UNSUPPORTED }
                    .map { it.message }
                    .distinct()
                    .take(4)
                if (reasons.isNotEmpty()) addView(Ui.text(c, R.style.Text_DPpass_Caption, reasons.joinToString("\n") { "• $it" }))
            }
            addView(Ui.text(c, R.style.Text_DPpass_Caption, c.getString(R.string.import_links_note)))
            addView(name, Ui.matchWidth())
            addView(
                Ui.button(c, R.string.import_links_add, Ui.Style.PRIMARY, R.drawable.ic_check).apply {
                    setOnClickListener {
                        val core = host.graph?.core ?: return@setOnClickListener
                        // Отказ (например, имя с управляющим символом) — окно остаётся: имя
                        // можно исправить, не начиная импорт заново.
                        when (val r = core.subscriptions.addInline(text, name.text.toString())) {
                            is Outcome.Failure -> host.problem(c.getString(Ui.kind(r.errors.first().kind)), r.errors.first())
                            is Outcome.Success -> {
                                sheet.dismiss()
                                refresh(host, r.value.id, r.value.name)
                            }
                        }
                        host.changed()
                    }
                },
                Ui.matchWidth(),
            )
        }
        sheet = Ui.sheet(c, c.getString(R.string.import_links_title), body)
        sheet.show()
    }

    /** Подписка по адресу: адрес (можно вставить), имя, пояснение; добавленная сразу загружается и применяется. */
    fun addSubscription(host: Host, prefill: String? = null) {
        val c = host.activity
        val url = Ui.field(c, R.string.subs_url_hint, InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_URI).apply {
            if (prefill != null) setText(prefill)
        }
        val name = Ui.field(c, R.string.subs_name_hint)
        lateinit var sheet: Dialog
        val body = Ui.column(c, 12).apply {
            addView(url, Ui.matchWidth())
            if (prefill == null) {
                addView(
                    Ui.button(c, R.string.paste, Ui.Style.TEXT, R.drawable.ic_paste).apply {
                        setOnClickListener {
                            val clip = c.getSystemService(ClipboardManager::class.java).primaryClip
                            clip?.takeIf { it.itemCount > 0 }?.getItemAt(0)?.coerceToText(c)?.toString()?.trim()?.let(url::setText)
                        }
                    },
                )
            }
            addView(name, Ui.matchWidth())
            addView(Ui.text(c, R.style.Text_DPpass_Caption, c.getString(R.string.subs_dialog_note)))
            addView(
                Ui.button(c, R.string.subs_add, Ui.Style.PRIMARY, R.drawable.ic_add).apply {
                    setOnClickListener {
                        val core = host.graph?.core ?: return@setOnClickListener
                        when (val r = core.subscriptions.add(url.text.toString(), name.text.toString())) {
                            is Outcome.Failure -> host.problem(c.getString(Ui.kind(r.errors.first().kind)), r.errors.first())
                            is Outcome.Success -> {
                                sheet.dismiss()
                                // Добавленная подписка сразу загружается и применяется: пустой подписке не из чего выбирать.
                                refresh(host, r.value.id, r.value.name)
                                host.showTab(Host.TAB_SUBSCRIPTIONS)
                            }
                        }
                        host.changed()
                    }
                },
                Ui.matchWidth(),
            )
        }
        sheet = Ui.sheet(c, c.getString(R.string.subs_dialog_title), body)
        sheet.show()
    }

    /**
     * Загрузить и применить подписку; итог — коротко или с причиной.
     * Туннель поднят, а подключённого сервера больше нет — переподключение (D-39).
     */
    fun refresh(host: Host, id: SubscriptionId, name: String) {
        val graph = host.graph ?: return
        val c = host.activity
        if (!running.add(id)) return
        host.changed()
        host.scope.launch {
            val r = try {
                withContext(Dispatchers.IO) { graph.core.subscriptions.refresh(id, graph.fetcher, graph.appVersion) }
            } finally {
                running.remove(id)
            }
            when (r) {
                is Outcome.Failure -> host.problem(c.getString(Ui.kind(r.errors.first().kind)), r.errors.first())
                is Outcome.Success -> {
                    val run = r.value
                    val activation = run.activation
                    when {
                        run.applied -> {
                            run.subscription.lastSuccessful?.profileCount.let { n ->
                                host.toast(c.resources.getQuantityString(R.plurals.subs_applied, n ?: 0, name, n ?: 0))
                            }
                            val connected = (TunnelState.status.value as? TunnelStatus.Connected)?.profileId
                            // Через устройство раздачи (D-55) туннель от серверов подписки не зависит.
                            val viaRelay = host.prefs.selectedRelay != null
                            if (!viaRelay && (TunnelState.status.value is TunnelStatus.Connecting || run.needsReconnect(connected))) host.reconnectIfBusy()
                        }
                        activation is ActivationResult.Rejected -> activation.diagnostics.firstOrNull { it.isError }?.let {
                            host.problem(c.getString(R.string.subs_not_applied, c.getString(Ui.kind(it.kind))), it)
                        }
                        run.update is UpdateResult.Failed -> run.update.diagnostics.firstOrNull { it.isError }?.let {
                            host.problem(c.getString(R.string.subs_not_applied, c.getString(Ui.kind(it.kind))), it)
                        }
                        else -> host.toast(c.getString(R.string.subs_unchanged))
                    }
                }
            }
            host.changed()
        }
    }

    /** Сколько невзятых записей профиля показать в сводке; остальные — числом. */
    private const val SKIPPED_SHOWN = 12

    /** Предел файла импорта — тот же, что у документа DPpass. */
    const val MAX_FILE_BYTES: Int = ImportClassifier.MAX_BYTES
}
