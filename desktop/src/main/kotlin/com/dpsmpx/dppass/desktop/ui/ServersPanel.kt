package com.dpsmpx.dppass.desktop.ui

import com.dpsmpx.dppass.config.ProtocolSpec
import com.dpsmpx.dppass.config.ServerProfile
import com.dpsmpx.dppass.core.Clock
import com.dpsmpx.dppass.core.ProfileId
import com.dpsmpx.dppass.desktop.DesktopGraph
import com.dpsmpx.dppass.desktop.DesktopPrefs
import com.dpsmpx.dppass.desktop.SessionStatus
import com.dpsmpx.dppass.network.LatencyResult
import com.dpsmpx.dppass.network.TcpLatencyProbe
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.awt.BorderLayout
import java.awt.Component
import java.awt.FlowLayout
import javax.swing.DefaultListCellRenderer
import javax.swing.DefaultListModel
import javax.swing.JList
import javax.swing.JPanel
import javax.swing.JScrollPane
import javax.swing.ListSelectionModel

/**
 * «Серверы»: серверы активной конфигурации, выбор пользователя (D-34) —
 * первым в плане; «Авто» — план сам (D-15). Задержка — по кнопке (D-41) и
 * только без туннеля: на Linux сокеты окна меток не ставят, и замер шёл бы
 * через туннель, а не до сервера.
 */
class ServersPanel(
    private val graph: DesktopGraph,
    private val prefs: DesktopPrefs,
    private val scope: CoroutineScope,
    private val status: () -> SessionStatus,
) : JPanel(BorderLayout()) {
    private data class Row(val id: ProfileId?, val title: String, val summary: String, val latency: String, val selected: Boolean, val connected: Boolean)

    private val model = DefaultListModel<Row>()
    private val list = JList(model)
    private val note = Widgets.caption()
    private val measureButton = Widgets.button("Проверить задержку") { measure() }
    private var measuring: Job? = null

    init {
        background = Theme.palette.bg
        border = Widgets.pad(4)
        list.selectionMode = ListSelectionModel.SINGLE_SELECTION
        list.cellRenderer = Renderer()
        list.addMouseListener(
            object : java.awt.event.MouseAdapter() {
                override fun mouseClicked(e: java.awt.event.MouseEvent) {
                    if (e.clickCount == 2) choose()
                }
            },
        )
        add(Widgets.title("Серверы").also { it.border = Widgets.pad(1) }, BorderLayout.NORTH)
        add(JScrollPane(list), BorderLayout.CENTER)
        val bottom = JPanel(BorderLayout()).apply {
            isOpaque = false
            add(note, BorderLayout.NORTH)
            add(
                JPanel(FlowLayout(FlowLayout.LEFT, Widgets.STEP * 2, Widgets.STEP * 2)).apply {
                    isOpaque = false
                    add(Widgets.button("Подключаться к выбранному") { choose() })
                    add(measureButton)
                },
                BorderLayout.CENTER,
            )
        }
        add(bottom, BorderLayout.SOUTH)
    }

    fun refresh() {
        val s = status()
        val connected = (s as? SessionStatus.Connected)?.profileId
        val profiles = graph.core.activation.state.activeConfig?.profiles.orEmpty()
        val selected = prefs.selectedServer?.takeIf { id -> profiles.any { it.id == id } }
        val keep = list.selectedIndex
        model.clear()
        if (profiles.isNotEmpty()) {
            model.addElement(Row(null, "Авто", "лучший по плану: последний удачный, затем по задержке и устойчивости", "", selected == null, false))
        }
        for (p in profiles) {
            model.addElement(Row(p.id, p.name, summary(p), latency(p.id), p.id == selected, p.id == connected))
        }
        if (keep in 0 until model.size()) list.selectedIndex = keep
        note.text = when {
            profiles.isEmpty() -> "Серверов нет: добавьте подписку или импортируйте ссылки из буфера обмена."
            s is SessionStatus.Connected || s is SessionStatus.Connecting -> "Задержка мерится без туннеля: отключитесь, чтобы проверить."
            else -> "Двойной щелчок или «Подключаться к выбранному» — этот сервер будет первым при подключении."
        }
        measureButton.isEnabled = profiles.isNotEmpty() && measuring?.isActive != true && s !is SessionStatus.Connected && s !is SessionStatus.Connecting
    }

    private fun choose() {
        val row = list.selectedValue ?: return
        prefs.selectedServer = row.id
        refresh()
    }

    private fun measure() {
        val profiles = graph.core.activation.state.activeConfig?.profiles.orEmpty()
        if (profiles.isEmpty() || measuring?.isActive == true) return
        measuring = scope.launch(Edt) {
            measureButton.isEnabled = false
            note.text = "Меряю задержку…"
            withContext(Dispatchers.IO) {
                graph.core.latency.measureAll(profiles, TcpLatencyProbe(Clock.MONOTONIC), { delay(it) }) { _, _ ->
                    scope.launch(Edt) { refresh() }
                }
            }
            measuring = null
            refresh()
        }
    }

    private fun latency(id: ProfileId): String = when (val r = graph.core.latency.of(id)) {
        null -> ""
        is LatencyResult.Measured -> "${r.millis} мс"
        is LatencyResult.Failed -> "нет ответа"
        LatencyResult.NotTcp -> "UDP — не мерится"
    }

    private fun summary(p: ServerProfile): String {
        val protocol = when (p.protocol) {
            is ProtocolSpec.Vless -> "VLESS"
            is ProtocolSpec.Trojan -> "Trojan"
            is ProtocolSpec.Shadowsocks -> "Shadowsocks"
            else -> p.protocol::class.simpleName ?: "?"
        }
        return "$protocol · ${p.transport::class.simpleName?.lowercase()} · ${p.security::class.simpleName?.lowercase()}"
    }

    private inner class Renderer : DefaultListCellRenderer() {
        override fun getListCellRendererComponent(list: JList<*>?, value: Any?, index: Int, isSelected: Boolean, cellHasFocus: Boolean): Component {
            val c = super.getListCellRendererComponent(list, value, index, isSelected, cellHasFocus)
            val r = value as Row
            val marks = listOfNotNull("подключён".takeIf { r.connected }, "выбран".takeIf { r.selected }).joinToString(" · ")
            text = "<html><b>${esc(r.title)}</b>${if (marks.isEmpty()) "" else " — " + esc(marks)}<br>" +
                "<span style='color:${hex(Theme.palette.textSecondary)}'>${esc(r.summary)}${if (r.latency.isEmpty()) "" else " · " + esc(r.latency)}</span></html>"
            border = Widgets.pad(2)
            return c
        }
    }

    private companion object {
        fun esc(s: String) = s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
        fun hex(c: java.awt.Color) = "#%02x%02x%02x".format(c.red, c.green, c.blue)
    }
}
