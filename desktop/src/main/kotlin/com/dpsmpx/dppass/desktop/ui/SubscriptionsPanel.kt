package com.dpsmpx.dppass.desktop.ui

import com.dpsmpx.dppass.connection.SubscriptionRun
import com.dpsmpx.dppass.core.SubscriptionId
import com.dpsmpx.dppass.desktop.DesktopGraph
import com.dpsmpx.dppass.diagnostics.Outcome
import com.dpsmpx.dppass.subscriptions.Subscription
import com.dpsmpx.dppass.subscriptions.SubscriptionSource
import com.dpsmpx.dppass.subscriptions.UpdatePolicy
import com.dpsmpx.dppass.subscriptions.UpdateSchedule
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.awt.BorderLayout
import java.awt.Component
import java.awt.FlowLayout
import java.awt.GridLayout
import javax.swing.DefaultListCellRenderer
import javax.swing.DefaultListModel
import javax.swing.JLabel
import javax.swing.JList
import javax.swing.JOptionPane
import javax.swing.JPanel
import javax.swing.JScrollPane
import javax.swing.JTextField
import javax.swing.ListSelectionModel

/**
 * «Подписки» (D-36): список, добавление по адресу `https://…`, обновление
 * (оно же применяет серверы подписки), удаление. Свои серверы (D-42) —
 * через импорт. Автообновление применённой подписки (D-77): интервал —
 * кнопкой «Автообновление…», у применённой — когда следующее. Списки
 * поставщика (D-94) — кнопкой «Списки поставщика…», маршрутизация и DNS
 * поставщика из документа DPpass (D-98) — «Маршрутизация поставщика…».
 */
class SubscriptionsPanel(
    private val graph: DesktopGraph,
    private val scope: CoroutineScope,
    /** После применения: серверы и состояние в окне — заново. */
    private val changed: () -> Unit,
    /**
     * Обновление применено: подключённого сервера в нём нет или он изменился —
     * переподключить (D-39); туннель без сервера (D-83) с первыми серверами —
     * тоже: дальше подключение через них.
     */
    private val applied: (SubscriptionRun) -> Unit = {},
    /** Смена маршрутизации без новых серверов (списки поставщика, D-94): переподключить, если туннель поднят. */
    private val reconnect: () -> Unit = {},
) : JPanel(BorderLayout()) {
    private val model = DefaultListModel<Subscription>()
    private val list = JList(model)
    private val note = Widgets.caption()
    private var activeId: SubscriptionId? = null
    private val running = mutableSetOf<SubscriptionId>()

    init {
        background = Theme.palette.bg
        border = Widgets.pad(4)
        list.selectionMode = ListSelectionModel.SINGLE_SELECTION
        list.cellRenderer = Renderer()
        add(Widgets.title("Подписки").also { it.border = Widgets.pad(1) }, BorderLayout.NORTH)
        add(JScrollPane(list), BorderLayout.CENTER)
        val bottom = JPanel(BorderLayout()).apply {
            isOpaque = false
            add(note, BorderLayout.NORTH)
            add(
                JPanel(FlowLayout(FlowLayout.LEFT, Widgets.STEP * 2, Widgets.STEP * 2)).apply {
                    isOpaque = false
                    add(Widgets.button("Добавить по адресу…") { addByUrl() })
                    add(Widgets.button("Обновить и применить") { list.selectedValue?.let { refresh(it.id, it.name) } })
                    add(Widgets.button("Автообновление…") { chooseInterval() })
                    add(
                        Widgets.button("Списки поставщика…") {
                            list.selectedValue?.let { s ->
                                ProviderListsDialog.show(this@SubscriptionsPanel, graph.core, scope, s, reconnect) {
                                    reload()
                                    changed()
                                }
                            }
                        },
                    )
                    add(
                        Widgets.button("Маршрутизация поставщика…") {
                            list.selectedValue?.let { s ->
                                ProviderPolicyDialog.show(this@SubscriptionsPanel, graph.core, scope, s, graph.fetcher, DesktopGraph.VERSION, reconnect) {
                                    reload()
                                    changed()
                                }
                            }
                        },
                    )
                    add(Widgets.button("Удалить…") { remove() })
                },
                BorderLayout.CENTER,
            )
        }
        add(bottom, BorderLayout.SOUTH)
    }

    fun reload() {
        val keep = list.selectedValue?.id
        model.clear()
        when (val s = graph.core.subscriptions.state()) {
            is Outcome.Failure -> note.text = "Подписки не прочитаны: ${s.errors.first().message}"
            is Outcome.Success -> {
                activeId = s.value.activeId
                s.value.items.forEach(model::addElement)
                note.text = if (s.value.items.isEmpty()) "Подписок нет. Добавьте адрес подписки или вставьте ссылки через «Импорт»." else " "
            }
        }
        keep?.let { id -> (0 until model.size()).firstOrNull { model[it].id == id }?.let { list.selectedIndex = it } }
    }

    fun addByUrl(prefill: String = "") {
        val url = JTextField(prefill, FIELD_COLUMNS)
        val name = JTextField(FIELD_COLUMNS)
        val form = JPanel(GridLayout(0, 1, 0, Widgets.STEP)).apply {
            add(JLabel("Адрес подписки (https://…):"))
            add(url)
            add(JLabel("Название (необязательно):"))
            add(name)
        }
        val answer = JOptionPane.showConfirmDialog(this, form, "Новая подписка", JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE)
        if (answer != JOptionPane.OK_OPTION) return
        when (val r = graph.core.subscriptions.add(url.text, name.text.ifBlank { null })) {
            is Outcome.Failure -> problem("Подписка не добавлена", Widgets.describe(r.errors.first()))
            is Outcome.Success -> {
                reload()
                refresh(r.value.id, r.value.name)
            }
        }
    }

    /** Загрузить и применить (D-36): серверы подписки становятся серверами активной конфигурации. */
    fun refresh(id: SubscriptionId, name: String) {
        if (!running.add(id)) return
        note.text = "Обновляю «$name»…"
        scope.launch(Edt) {
            val r = withContext(Dispatchers.IO) { graph.core.subscriptions.refresh(id, graph.fetcher, DesktopGraph.VERSION) }
            running.remove(id)
            reload()
            changed()
            when (r) {
                is Outcome.Failure -> problem("«$name» не обновлена", Widgets.describe(r.errors.first()))
                is Outcome.Success -> {
                    val run = r.value
                    applied(run)
                    val failed = run.diagnostics.firstOrNull { it.isError }
                    note.text = when {
                        run.applied -> "«$name»: серверов — ${run.after?.profiles?.size ?: 0}, применено."
                        failed != null -> "«$name» не применена: ${failed.message}"
                        else -> "«$name»: без изменений."
                    }
                }
            }
        }
    }

    /** Интервал автообновления (D-39, D-77): выкл, 6, 12 или 24 часа, как на Android. */
    private fun chooseInterval() {
        val s = list.selectedValue ?: return
        if (s.source !is SubscriptionSource.Url) {
            problem("Автообновление", "«${s.name}» — свои серверы: загружать их неоткуда, автообновление им не нужно.")
            return
        }
        val choices = UpdatePolicy.CHOICES_MINUTES
        val labels = choices.map(::interval).toTypedArray()
        val current = labels[choices.indexOf(s.updatePolicy.intervalMinutes).coerceAtLeast(0)]
        val picked = JOptionPane.showInputDialog(
            this,
            "Как часто обновлять «${s.name}», пока открыто окно DPpass (только применённую подписку):",
            "Автообновление",
            JOptionPane.PLAIN_MESSAGE,
            null,
            labels,
            current,
        ) ?: return
        when (val r = graph.core.subscriptions.setUpdateInterval(s.id, choices[labels.indexOf(picked)])) {
            is Outcome.Failure -> problem("Не сохранено", Widgets.describe(r.errors.first()))
            is Outcome.Success -> reload()
        }
    }

    private fun remove() {
        val s = list.selectedValue ?: return
        val ok = JOptionPane.showConfirmDialog(this, "Удалить подписку «${s.name}»?", "Удаление", JOptionPane.OK_CANCEL_OPTION) == JOptionPane.OK_OPTION
        if (!ok) return
        when (val r = graph.core.subscriptions.remove(s.id)) {
            is Outcome.Failure -> problem("Не удалена", Widgets.describe(r.errors.first()))
            is Outcome.Success -> {
                reload()
                changed()
            }
        }
    }

    private fun problem(title: String, text: String) {
        JOptionPane.showMessageDialog(this, Widgets.note().also { it.text = text; it.columns = FIELD_COLUMNS }, title, JOptionPane.WARNING_MESSAGE)
    }

    private inner class Renderer : DefaultListCellRenderer() {
        override fun getListCellRendererComponent(list: JList<*>?, value: Any?, index: Int, isSelected: Boolean, cellHasFocus: Boolean): Component {
            val c = super.getListCellRendererComponent(list, value, index, isSelected, cellHasFocus)
            val s = value as Subscription
            val kind = when (s.source) {
                is SubscriptionSource.Url -> "по адресу"
                else -> "свои серверы"
            }
            val parts = buildList {
                add(kind)
                s.lastSuccessful?.let { add("серверов: ${it.profileCount}") }
                (s.lastCheckedMillis ?: s.lastSuccessful?.fetchedAtMillis)?.let { add("проверена ${Format.date(it)}") }
                s.lastFailed?.let { add("ошибка: ${it.reason.message}") }
                if (s.source is SubscriptionSource.Url) add(autoUpdate(s))
                if (s.providerProfile != null) add(if (s.useProviderLists) "списки поставщика включены" else "списки поставщика получены")
            }
            val active = if (s.id == activeId) " — применена" else ""
            text = "<html><b>${esc(s.name)}</b>${esc(active)}<br><span>${esc(parts.joinToString(" · "))}</span></html>"
            border = Widgets.pad(2)
            return c
        }
    }

    /** Автообновление подписки: выключено, когда следующее у применённой — или что оно только у применённой (D-77). */
    private fun autoUpdate(s: Subscription): String {
        val every = s.updatePolicy.intervalMinutes ?: return "автообновление выключено"
        val now = graph.core.clock.nowMillis()
        val next = if (s.id == activeId) UpdateSchedule.waitMillis(s, now) else null
        val note = if (next != null) "следующее — ${Format.date(now + next)}" else "только у применённой"
        return "автообновление ${interval(every)}, $note"
    }

    private companion object {
        const val FIELD_COLUMNS = 40

        fun interval(minutes: Long?): String = if (minutes == null) "выключено" else "каждые ${minutes / 60} ч"

        fun esc(s: String) = s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    }
}
