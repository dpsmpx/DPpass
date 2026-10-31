package com.dpsmpx.dppass.desktop.ui

import com.dpsmpx.dppass.connection.ShareSettings
import com.dpsmpx.dppass.desktop.DesktopGraph
import com.dpsmpx.dppass.desktop.DesktopSession
import com.dpsmpx.dppass.desktop.DesktopShares
import com.dpsmpx.dppass.desktop.SessionStatus
import com.dpsmpx.dppass.desktop.ShareStatus
import com.dpsmpx.dppass.diagnostics.Outcome
import com.dpsmpx.dppass.engine.ServerlessPlan
import java.awt.BorderLayout
import java.awt.FlowLayout
import java.awt.GridBagConstraints
import java.awt.GridBagLayout
import java.awt.Insets
import javax.swing.Box
import javax.swing.JCheckBox
import javax.swing.JComponent
import javax.swing.JLabel
import javax.swing.JOptionPane
import javax.swing.JPanel
import javax.swing.JPasswordField
import javax.swing.JTextField

/**
 * «Раздача» (D-84, D-101, к D-51): вход прокси SOCKS5 и HTTP с паролем на
 * адресах точки доступа ПК — для других устройств в ней; где она, говорит
 * система ([DesktopShares]). Включить, адреса, порт,
 * логин и пароль, новые логин, пароль и порт. Включение и смена входа
 * действуют сразу: туннель переподключается. Пароль скрыт, пока его не
 * показали: на ПК нет запрета снимка экрана, как `FLAG_SECURE` на Android.
 */
class SharePanel(private val graph: DesktopGraph, private val session: DesktopSession, private val shares: DesktopShares) : JPanel(BorderLayout()) {
    private val enabled = JCheckBox("Раздавать туннель").apply {
        isOpaque = false
        foreground = Theme.palette.text
        addActionListener { switch(isSelected) }
    }
    private val where = Widgets.still(Widgets.note())
    private val problem = Widgets.Banner(error = false)
    private val address = field()
    private val port = field()
    private val user = field()
    private val password = JPasswordField().apply { isEditable = false }
    private val masked = password.echoChar
    private var last: SessionStatus = SessionStatus.Disconnected
    private var lastShare: ShareStatus? = null

    /** Последнее несохранённое изменение — до следующего удачного. */
    private var failure: String? = null

    init {
        background = Theme.palette.bg
        border = Widgets.pad(4)
        val column = Widgets.Column()
        column.line(Widgets.title("Раздача туннеля").also { it.border = Widgets.pad(1) })
        column.line(Widgets.still(Widgets.note()).apply { text = INTRO })
        column.add(Box.createVerticalStrut(Widgets.STEP * 2))
        column.line(enabled)
        column.line(Widgets.caption(shares.condition))
        column.add(Box.createVerticalStrut(Widgets.STEP * 2))
        column.line(where)
        column.line(problem)
        column.add(Box.createVerticalStrut(Widgets.STEP * 2))
        column.line(credentials())
        column.add(Box.createVerticalStrut(Widgets.STEP * 2))
        column.line(
            JPanel(FlowLayout(FlowLayout.LEFT, 0, 0)).apply {
                isOpaque = false
                add(Widgets.button("Новые логин, пароль и порт") { regenerate() })
            },
        )
        column.line(Widgets.caption("Другим устройствам понадобятся новые настройки"))
        column.add(Box.createVerticalStrut(Widgets.STEP * 4))
        column.line(Widgets.title("Важно знать").also { it.border = Widgets.pad(1) })
        column.line(Widgets.still(Widgets.note()).apply { text = limits(shares.firewall) })
        add(column.scroll(), BorderLayout.CENTER)
        reload()
    }

    /** Состояние сеанса и его раздачи — из потоков `DesktopSession`, на потоке EDT. */
    fun render(status: SessionStatus, share: ShareStatus?) {
        last = status
        lastShare = share
        val read = graph.core.share.current()
        val settings = read.valueOrNull()
        val on = settings?.enabled == true
        val connected = status as? SessionStatus.Connected
        val (text, warning) = when {
            read is Outcome.Failure -> " " to "Настройки раздачи не прочитаны: ${read.errors.first().message}"
            !on -> "Раздача выключена." to null
            connected == null -> "Адреса появятся, когда DPpass подключится." to null
            connected.profileId == ServerlessPlan.PROFILE_ID -> " " to "Без сервера раздачи нет: она — вход в туннель через сервер."
            share == null -> "Адреса появятся после переподключения." to null
            share.refused -> " " to REFUSED
            share.endpoints.isEmpty() -> " " to share.absent
            else -> "Адрес прокси — для другого устройства (SOCKS5 или HTTP):" to null
        }
        where.text = text
        problem.show(warning ?: failure)
        address.text = share?.takeIf { on && connected != null && !it.refused }?.endpoints.orEmpty().joinToString("  ") { "${it.address}:${settings?.port}" }
        revalidate()
        repaint()
    }

    /** Настройки раздачи с диска: переключатель и вход. */
    fun reload() {
        graph.core.share.current().valueOrNull()?.let(::show)
        render(last, lastShare)
    }

    private fun show(s: ShareSettings) {
        enabled.isSelected = s.enabled
        port.text = s.port.toString()
        user.text = s.user.reveal()
        password.text = s.password.reveal()
    }

    private fun credentials(): JPanel = JPanel(GridBagLayout()).apply {
        isOpaque = false
        val reveal = JCheckBox("Показать").apply {
            isOpaque = false
            foreground = Theme.palette.text
            addActionListener { password.echoChar = if (isSelected) '\u0000' else masked }
        }
        val rows = listOf<Triple<String, JComponent, () -> String>>(
            Triple("Адрес", address) { address.text },
            Triple("Порт", port) { port.text },
            Triple("Логин", user) { user.text },
            Triple("Пароль", password) { String(password.password) },
        )
        for ((i, row) in rows.withIndex()) {
            val (label, value, copy) = row
            add(JLabel(label).apply { foreground = Theme.palette.textSecondary }, cell(0, i))
            add(value, cell(1, i).apply { fill = GridBagConstraints.HORIZONTAL; weightx = 1.0 })
            add(Widgets.button("Скопировать") { copy(copy()) }, cell(2, i))
            if (value === password) add(reveal, cell(3, i))
        }
    }

    private fun switch(on: Boolean) {
        when (val r = graph.core.share.setEnabled(on)) {
            is Outcome.Failure -> {
                enabled.isSelected = !on
                failure = "Настройки раздачи не сохранены: ${r.errors.first().message}"
            }
            is Outcome.Success -> {
                failure = null
                show(r.value)
                graph.core.log.info("share_set", "on" to on)
                session.reconnectIfConnected()
            }
        }
        render(last, lastShare)
    }

    private fun regenerate() {
        val answer = JOptionPane.showConfirmDialog(
            this,
            "Сменить логин, пароль и порт? Устройства со старыми настройками перестанут работать через ПК.",
            "Новые логин, пароль и порт",
            JOptionPane.OK_CANCEL_OPTION,
            JOptionPane.WARNING_MESSAGE,
        )
        if (answer != JOptionPane.OK_OPTION) return
        when (val r = graph.core.share.regenerate()) {
            is Outcome.Failure -> failure = "Настройки раздачи не сохранены: ${r.errors.first().message}"
            is Outcome.Success -> {
                failure = null
                show(r.value)
                graph.core.log.info("share_regenerated")
                if (r.value.enabled) session.reconnectIfConnected()
            }
        }
        render(last, lastShare)
    }

    private fun copy(text: String) {
        if (text.isBlank()) return
        // Пароль — не в историю буфера Windows и не в облачный буфер (обзор 0.7.48, F-1).
        SecretClipboard.copy(text)
    }

    private companion object {
        fun field() = JTextField(FIELD_COLUMNS).apply { isEditable = false }

        fun cell(x: Int, y: Int) = GridBagConstraints().apply {
            gridx = x
            gridy = y
            anchor = GridBagConstraints.WEST
            insets = Insets(Widgets.STEP, 0, Widgets.STEP, Widgets.STEP * 2)
        }

        const val FIELD_COLUMNS = 18

        const val INTRO = "Ваши другие устройства могут ходить в интернет через туннель DPpass: ПК открывает прокси с паролем " +
            "на адресе своей точки доступа, а другое устройство указывает его у себя."

        const val REFUSED = "Прокси не открылся на адресе точки доступа: её выключили во время подключения, или порт занят " +
            "другой программой. Туннель работает без раздачи. Включите точку доступа заново или нажмите «Новые логин, пароль и порт»."

        /** «Важно знать»; [firewall] — строка о межсетевом экране этой системы. */
        fun limits(firewall: String): String = "• На другом устройстве нужна программа, которая умеет работать через прокси. Надёжнее всего — " +
            "клиент SOCKS5 с паролем; HTTP-прокси в настройках Wi-Fi пароль не передаёт: браузер спросит его сам, остальные " +
            "программы могут не работать.\n" +
            "• Через прокси идёт только то, что программа другого устройства в него направила, и её DNS тоже.\n" +
            "• Маршрутизация и блокировка — те же, что у ПК.\n" +
            "$firewall\n" +
            "• Пока раздача включена, открытый порт видят устройства в точке доступа и программы ПК — это примета прокси. " +
            "Выключайте раздачу, когда она не нужна."
    }
}
