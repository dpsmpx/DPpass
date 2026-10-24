package com.dpsmpx.dppass.desktop.ui

import com.dpsmpx.dppass.desktop.DesktopGraph
import com.dpsmpx.dppass.desktop.DesktopPrefs
import com.dpsmpx.dppass.desktop.DesktopSession
import com.dpsmpx.dppass.diagnostics.Diagnostic
import com.dpsmpx.dppass.diagnostics.Outcome
import com.dpsmpx.dppass.routing.SplitSites
import java.awt.BorderLayout
import java.awt.Component
import javax.swing.JOptionPane
import javax.swing.JPanel
import javax.swing.JScrollPane
import javax.swing.JTextArea

/**
 * Правка списка «Напрямую с разбиением» (D-72, D-82): запись на строку —
 * домен с поддоменами или список geosite. Неверная строка или код geosite,
 * которого нет в наборе (D-27), — ошибка, и окно открывается снова с тем же
 * текстом; сохраняется только разобранный список. Действует сразу —
 * туннель переподключается.
 */
object SplitSitesDialog {
    fun show(parent: Component, graph: DesktopGraph, prefs: DesktopPrefs, session: DesktopSession) {
        var text = prefs.splitSitesText
        while (true) {
            val area = JTextArea(text, ROWS, COLUMNS)
            val form = JPanel(BorderLayout(0, Widgets.STEP * 2)).apply {
                add(Widgets.note().apply { this.text = NOTE; columns = COLUMNS }, BorderLayout.NORTH)
                add(JScrollPane(area), BorderLayout.CENTER)
            }
            val answer = JOptionPane.showConfirmDialog(parent, form, "Сайты напрямую с разбиением", JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE)
            if (answer != JOptionPane.OK_OPTION) return
            text = area.text
            when (val r = validate(text, graph.core::checkSplitSites)) {
                is Outcome.Failure -> JOptionPane.showMessageDialog(
                    parent,
                    r.errors.joinToString("\n") { it.message },
                    "Список не сохранён",
                    JOptionPane.WARNING_MESSAGE,
                )
                is Outcome.Success -> {
                    prefs.splitSitesText = r.value.format()
                    graph.core.log.info("split_sites_set", "n" to r.value.size)
                    session.reconnectIfConnected()
                    return
                }
            }
        }
    }

    /** Текст → список: разбор (номер строки у ошибки) и проверка кодов geosite по набору ядра. */
    fun validate(text: String, check: (SplitSites) -> List<Diagnostic>): Outcome<SplitSites> {
        val sites = when (val parsed = SplitSites.parse(text)) {
            is Outcome.Failure -> return parsed
            is Outcome.Success -> parsed.value
        }
        val problems = check(sites).filter { it.isError }
        return if (problems.isEmpty()) Outcome.Success(sites) else Outcome.Failure(problems)
    }

    private const val ROWS = 10
    private const val COLUMNS = 50

    private const val NOTE = "Запись на строку: домен с поддоменами (example.com) или список из набора геоданных (geosite:youtube). " +
        "TCP к этим сайтам идёт напрямую, мимо сервера, а начало TLS — мелкими частями; QUIC (UDP 443) к ним закрыт, и программы " +
        "переходят на TCP. Может помочь против фильтров, которые ищут имя сайта; не помогает, если закрыт сам адрес. Действует сразу."
}
