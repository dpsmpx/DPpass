package com.dpsmpx.dppass.desktop.ui

import com.dpsmpx.dppass.connection.UsageService
import com.dpsmpx.dppass.connection.UsageSettings
import com.dpsmpx.dppass.diagnostics.Outcome
import java.awt.Component
import java.awt.GridBagConstraints
import java.awt.GridBagLayout
import java.awt.Insets
import javax.swing.JLabel
import javax.swing.JOptionPane
import javax.swing.JPanel
import javax.swing.JSpinner
import javax.swing.JTextField
import javax.swing.SpinnerNumberModel

/**
 * «Трафик через сервер» (D-92): сегодня и расчётный период по сетям,
 * день начала периода и порог мобильной сети, сброс с подтверждением.
 * Порог только предупреждает — туннель не отключается.
 */
object UsageDialog {
    private const val OPTION_SAVE = 0
    private const val OPTION_RESET = 1

    fun show(parent: Component, usage: UsageService) {
        while (true) {
            val s = usage.summary()
            val day = JSpinner(SpinnerNumberModel(s.settings.periodStartDay, UsageSettings.DAYS.first, UsageSettings.DAYS.last, 1))
            val limit = JTextField(s.settings.mobileLimitBytes?.let(UsageSettings::gigabytes).orEmpty(), FIELD_COLUMNS)
            val form = JPanel(GridBagLayout())
            var y = 0
            fun row(label: String, value: Component) {
                form.add(JLabel(label), cell(0, y))
                form.add(value, cell(1, y).apply { fill = GridBagConstraints.HORIZONTAL; weightx = 1.0 })
                y++
            }
            fun section(text: String) {
                form.add(JLabel("<html><b>$text</b></html>"), cell(0, y).apply { gridwidth = 2 })
                y++
            }
            section("Сегодня")
            UsageText.networks(s.today).forEach { (name, b) -> row(name, JLabel(UsageText.bytes(b))) }
            section("${UsageText.day(s.periodStart)} – ${UsageText.day(s.periodEnd.minusDays(1))}")
            UsageText.networks(s.period).forEach { (name, b) -> row(name, JLabel(UsageText.bytes(b))) }
            s.resetAtMillis?.let { row("Сброс", JLabel(Format.date(it))) }
            section("Настройки")
            row("Начало периода, число месяца", day)
            row("Порог мобильной сети, ГБ (пусто — нет)", limit)
            form.add(Widgets.note().apply { text = UsageText.NOTE; columns = NOTE_COLUMNS }, cell(0, y).apply { gridwidth = 2 })
            val options = arrayOf("Сохранить", "Сбросить счётчики", "Закрыть")
            when (JOptionPane.showOptionDialog(parent, form, "Трафик через сервер", 0, JOptionPane.PLAIN_MESSAGE, null, options, options[0])) {
                OPTION_SAVE -> {
                    val text = limit.text.trim()
                    val bytes = if (text.isEmpty()) null else UsageSettings.parseGigabytes(text)
                    if (text.isNotEmpty() && bytes == null) {
                        val why = "Порог — число гигабайт больше нуля, например 15 или 1,5"
                        JOptionPane.showMessageDialog(parent, why, "Не сохранено", JOptionPane.WARNING_MESSAGE)
                        continue
                    }
                    when (val r = usage.setSettings(UsageSettings((day.value as Number).toInt(), bytes))) {
                        is Outcome.Failure -> JOptionPane.showMessageDialog(parent, r.errors.first().message, "Не сохранено", JOptionPane.WARNING_MESSAGE)
                        is Outcome.Success -> return
                    }
                }
                OPTION_RESET -> {
                    val sure = JOptionPane.showConfirmDialog(
                        parent,
                        "Сбросить счётчики за сегодня и этот период? Прошлые периоды останутся.",
                        "Сбросить счётчики",
                        JOptionPane.OK_CANCEL_OPTION,
                        JOptionPane.WARNING_MESSAGE,
                    )
                    if (sure == JOptionPane.OK_OPTION) {
                        (usage.reset() as? Outcome.Failure)?.let {
                            JOptionPane.showMessageDialog(parent, it.errors.first().message, "Не сброшено", JOptionPane.WARNING_MESSAGE)
                        }
                    }
                }
                else -> return
            }
        }
    }

    private fun cell(x: Int, y: Int) = GridBagConstraints().apply {
        gridx = x
        gridy = y
        anchor = GridBagConstraints.WEST
        insets = Insets(Widgets.STEP, 0, Widgets.STEP, Widgets.STEP * 2)
    }

    private const val FIELD_COLUMNS = 8
    private const val NOTE_COLUMNS = 48
}
