package com.dpsmpx.dppass.desktop.ui

import com.dpsmpx.dppass.connection.DPpassCore
import com.dpsmpx.dppass.connection.LocalProxySettings
import com.dpsmpx.dppass.diagnostics.Outcome
import com.dpsmpx.dppass.engine.LocalProxySpec
import java.awt.BorderLayout
import java.awt.Component
import java.awt.GridBagConstraints
import java.awt.GridBagLayout
import java.awt.Insets
import java.awt.Toolkit
import java.awt.datatransfer.StringSelection
import javax.swing.JCheckBox
import javax.swing.JComponent
import javax.swing.JLabel
import javax.swing.JOptionPane
import javax.swing.JPanel
import javax.swing.JPasswordField
import javax.swing.JTextField

/**
 * «Подключение без VPN» на ПК (D-95) — то же, что на телефоне: вместо TUN
 * DPpass открывает прокси SOCKS5 и HTTP с логином и паролем на 127.0.0.1 —
 * через сервер идут только программы, где он указан; права CAP_NET_ADMIN
 * не нужны. Здесь — включить, адрес, порт, логин и пароль с копированием и
 * смена порта и пароля. Смена при поднятом подключении — переподключение.
 * Пароль скрыт, пока его не показали: запрета снимка экрана на ПК нет.
 */
object LocalProxyDialog {
    fun show(parent: Component, core: DPpassCore, reconnect: () -> Unit, changed: () -> Unit) {
        val current = when (val r = core.localProxy.current()) {
            is Outcome.Failure -> return JOptionPane.showMessageDialog(parent, Widgets.describe(r.errors.first()), TITLE, JOptionPane.WARNING_MESSAGE)
            is Outcome.Success -> r.value
        }
        val port = field()
        val user = field()
        val password = JPasswordField().apply { isEditable = false }
        val masked = password.echoChar
        var settings = current
        fun fill(s: LocalProxySettings) {
            settings = s
            port.text = s.port.toString()
            user.text = s.user.reveal()
            password.text = s.password.reveal()
        }
        fill(current)
        val problem = Widgets.Banner(error = false)
        fun apply(event: String, change: () -> Outcome<LocalProxySettings>) {
            when (val r = change()) {
                is Outcome.Failure -> problem.show("Не сохранено: ${r.errors.first().message}")
                is Outcome.Success -> {
                    problem.show(null)
                    fill(r.value)
                    core.log.info(event, "enabled" to r.value.enabled)
                    reconnect()
                    changed()
                }
            }
        }
        val enabled = JCheckBox("Подключаться без VPN", current.enabled).apply {
            isOpaque = false
            foreground = Theme.palette.text
            addActionListener { apply("local_proxy_switched") { core.localProxy.setEnabled(isSelected) } }
        }
        val reveal = JCheckBox("Показать").apply {
            isOpaque = false
            foreground = Theme.palette.text
            addActionListener { password.echoChar = if (isSelected) '\u0000' else masked }
        }
        val grid = JPanel(GridBagLayout()).apply {
            isOpaque = false
            val rows = listOf<Triple<String, JComponent, () -> String>>(
                Triple("Адрес", field().apply { text = LocalProxySpec.ADDRESS }) { LocalProxySpec.ADDRESS },
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
            add(Widgets.button("Скопировать ссылку socks5://") { copy(settings.link()) }, cell(1, rows.size))
            add(
                Widgets.button("Сменить порт и пароль…") {
                    val answer = JOptionPane.showConfirmDialog(
                        this,
                        "Новые порт и пароль? Программы, где указан прокси, перестанут идти через DPpass, пока вы не укажете новые.",
                        TITLE,
                        JOptionPane.OK_CANCEL_OPTION,
                        JOptionPane.WARNING_MESSAGE,
                    )
                    if (answer == JOptionPane.OK_OPTION) apply("local_proxy_regenerated") { core.localProxy.regenerate() }
                },
                cell(2, rows.size).apply { gridwidth = 2 },
            )
        }
        val form = JPanel(BorderLayout(0, Widgets.STEP * 2)).apply {
            isOpaque = false
            add(enabled, BorderLayout.NORTH)
            add(grid, BorderLayout.CENTER)
            add(
                JPanel(BorderLayout(0, Widgets.STEP)).apply {
                    isOpaque = false
                    add(Widgets.note().apply { text = NOTE; columns = NOTE_COLUMNS }, BorderLayout.CENTER)
                    add(problem, BorderLayout.SOUTH)
                },
                BorderLayout.SOUTH,
            )
        }
        JOptionPane.showMessageDialog(parent, form, TITLE, JOptionPane.PLAIN_MESSAGE)
    }

    /**
     * Строка панели подключения: режим выключен — null; подключено — куда
     * направить программы; иначе — что режим включён и какой будет адрес.
     */
    fun line(settings: LocalProxySettings?, connected: LocalProxySpec?): String? = when {
        connected != null -> "Без VPN · укажите в программах прокси ${LocalProxySpec.ADDRESS}:${connected.port}"
        settings?.enabled == true -> "Без VPN включено · прокси ${LocalProxySpec.ADDRESS}:${settings.port}"
        else -> null
    }

    private fun copy(text: String) {
        if (text.isBlank()) return
        Toolkit.getDefaultToolkit().systemClipboard.setContents(StringSelection(text), null)
    }

    private fun field() = JTextField(FIELD_COLUMNS).apply { isEditable = false }

    private fun cell(x: Int, y: Int) = GridBagConstraints().apply {
        gridx = x
        gridy = y
        anchor = GridBagConstraints.WEST
        insets = Insets(Widgets.STEP, Widgets.STEP, Widgets.STEP, Widgets.STEP)
    }

    const val TITLE: String = "Подключение без VPN"
    private const val FIELD_COLUMNS = 24
    private const val NOTE_COLUMNS = 60
    private const val NOTE = "Прокси SOCKS5 и HTTP на одном порту, только для программ этого ПК (127.0.0.1). Программы без настройки прокси " +
        "идут мимо DPpass, как без него. Права CAP_NET_ADMIN не нужны. Режим без сервера работает только через VPN."
}
