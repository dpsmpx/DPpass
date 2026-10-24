package com.dpsmpx.dppass.desktop.ui

import com.dpsmpx.dppass.core.Clock
import com.dpsmpx.dppass.desktop.DesktopGraph
import com.dpsmpx.dppass.desktop.DesktopPrefs
import com.dpsmpx.dppass.desktop.DesktopSession
import com.dpsmpx.dppass.desktop.ServerNotice
import com.dpsmpx.dppass.desktop.SessionStatus
import java.awt.BorderLayout
import java.awt.Component
import java.awt.FlowLayout
import javax.swing.BoxLayout
import javax.swing.JPanel
import javax.swing.Timer

/**
 * «Подключение»: кнопка питания, состояние, сервер, время и трафик сеанса,
 * причина отказа; сбой выбранного сервера (D-58, D-78) — вопрос с кнопками
 * «Перейти» и «Остаться» или сообщение об автопереключении.
 */
class ConnectPanel(
    private val graph: DesktopGraph,
    private val session: DesktopSession,
    private val prefs: DesktopPrefs,
    private val import: () -> Unit,
) : JPanel(BorderLayout()) {
    private val power = PowerButton(::toggle)
    private val state = Widgets.title("Отключено")
    private val server = Widgets.caption()
    private val details = Widgets.caption()
    private val reason = Widgets.Banner(error = true)
    private val rights = Widgets.Banner(error = false)
    private val offerText = Widgets.Banner(error = false)
    private val offerButtons = JPanel(FlowLayout(FlowLayout.CENTER, Widgets.STEP * 2, 0)).apply {
        isOpaque = false
        isVisible = false
    }
    private var last: SessionStatus = SessionStatus.Disconnected
    private val ticker = Timer(TICK_MILLIS) { renderDetails() }

    init {
        background = Theme.palette.bg
        border = Widgets.pad(6)
        val column = JPanel().apply {
            isOpaque = false
            layout = BoxLayout(this, BoxLayout.Y_AXIS)
        }
        fun center(c: javax.swing.JComponent) = c.also { it.alignmentX = Component.CENTER_ALIGNMENT }
        column.add(center(rights))
        column.add(javax.swing.Box.createVerticalStrut(Widgets.STEP))
        column.add(center(offerText))
        column.add(center(offerButtons))
        column.add(javax.swing.Box.createVerticalGlue())
        column.add(center(power))
        column.add(javax.swing.Box.createVerticalStrut(Widgets.STEP * 4))
        column.add(center(state))
        column.add(javax.swing.Box.createVerticalStrut(Widgets.STEP))
        column.add(center(server))
        column.add(center(details))
        column.add(javax.swing.Box.createVerticalStrut(Widgets.STEP * 4))
        column.add(center(reason))
        column.add(javax.swing.Box.createVerticalGlue())
        add(column, BorderLayout.CENTER)
        val actions = JPanel(FlowLayout(FlowLayout.CENTER, Widgets.STEP * 2, 0)).apply {
            isOpaque = false
            add(Widgets.button("Импорт из буфера обмена…") { import() })
        }
        add(actions, BorderLayout.SOUTH)
        val problems = buildList {
            if (!graph.platform.hasNetAdmin()) {
                add(
                    "DPpass запущен без права CAP_NET_ADMIN — подключение невозможно. Запустите его ярлыком DPpass " +
                        "или командой dppass: пароль администратора нужен для запуска с одной этой возможностью (D-74).",
                )
            }
            graph.problems.forEach { add(Widgets.describe(it)) }
        }
        rights.show(problems.joinToString("\n\n").ifEmpty { null })
        ticker.start()
        render(SessionStatus.Disconnected)
    }

    fun render(s: SessionStatus) {
        last = s
        val p = Theme.palette
        val (fill, ring, title) = when (s) {
            SessionStatus.Disconnected -> Triple(p.surfaceVariant, p.outline, "Отключено")
            is SessionStatus.Connecting -> Triple(p.primaryContainer, p.primary, "Подключаю…")
            is SessionStatus.Connected -> Triple(p.successContainer, p.success, "Подключено")
            SessionStatus.Disconnecting -> Triple(p.surfaceVariant, p.primary, "Отключаю…")
            is SessionStatus.Failed -> Triple(p.errorContainer, p.error, "Не подключилось")
        }
        power.fill = fill
        power.ring = ring
        power.isEnabled = s !is SessionStatus.Disconnecting
        state.text = title
        reason.show((s as? SessionStatus.Failed)?.reason?.let(Widgets::describe))
        renderDetails()
    }

    /** Сбой выбранного сервера (D-58): вопрос — с ответами; сообщение об автопереключении — с «Понятно». */
    fun renderNotice(n: ServerNotice?) {
        offerButtons.removeAll()
        if (n == null) {
            offerText.show(null)
            offerButtons.isVisible = false
            return
        }
        val why = n.reason.message
        if (n.asked) {
            offerText.show(
                "Сервер «${n.from.name}» перестал отвечать: $why\n\n" +
                    "Перейти на «${n.to.name}»? Пока ответа нет, DPpass переподключается к «${n.from.name}».",
            )
            offerButtons.add(Widgets.button("Перейти на «${n.to.name}»") { session.acceptSwitch() })
            offerButtons.add(Widgets.button("Остаться") { session.keepServer() })
        } else {
            offerText.show("DPpass перешёл с «${n.from.name}» на «${n.to.name}» (автопереключение): $why")
            offerButtons.add(Widgets.button("Понятно") { session.dismissNotice() })
        }
        offerButtons.isVisible = true
        revalidate()
        repaint()
    }

    private fun renderDetails() {
        val s = last
        server.text = when (s) {
            is SessionStatus.Connected -> "Сервер: ${s.server}"
            is SessionStatus.Connecting -> s.server?.let { "Пробую: $it" } ?: "Готовлю туннель"
            else -> relayName()?.let { "Через устройство раздачи: $it" } ?: ("Сервер: " + (selectedName() ?: "авто — лучший по плану"))
        }
        details.text = if (s is SessionStatus.Connected) {
            val t = session.traffic()
            val since = Format.duration(Clock.SYSTEM.nowMillis() - s.sinceMillis)
            if (t == null) since else "$since · ↑ ${Format.bytes(t.uplinkBytes)} · ↓ ${Format.bytes(t.downlinkBytes)}"
        } else {
            " "
        }
    }

    /** Выбранное устройство раздачи (D-85): подключение пойдёт только через него. */
    private fun relayName(): String? = prefs.selectedRelay?.let(graph.core.relays::find)?.name

    private fun selectedName(): String? {
        val id = prefs.selectedServer ?: return null
        return graph.core.activation.state.activeConfig?.profiles?.firstOrNull { it.id == id }?.name
    }

    private fun toggle() {
        when (last) {
            is SessionStatus.Connected, is SessionStatus.Connecting -> session.disconnect()
            SessionStatus.Disconnecting -> Unit
            else -> session.connect(prefs.selectedServer)
        }
    }

    private companion object {
        const val TICK_MILLIS = 1000
    }
}
