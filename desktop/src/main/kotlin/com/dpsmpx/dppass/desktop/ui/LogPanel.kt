package com.dpsmpx.dppass.desktop.ui

import com.dpsmpx.dppass.desktop.DesktopGraph
import java.awt.BorderLayout
import java.awt.FlowLayout
import java.awt.Font
import java.awt.Toolkit
import java.awt.datatransfer.StringSelection
import javax.swing.JPanel
import javax.swing.JScrollPane
import javax.swing.JTextArea

/**
 * «Журнал»: события этого запуска из памяти (D-26, D-54) — уже с
 * отредактированными секретами (`Logger`, D-11). Наружу — только кнопкой
 * «Копировать журнал» (D-47).
 */
class LogPanel(private val graph: DesktopGraph) : JPanel(BorderLayout()) {
    private val area = JTextArea().apply {
        isEditable = false
        font = Font(Font.MONOSPACED, Font.PLAIN, MONO_SIZE)
        background = Theme.palette.surface
        foreground = Theme.palette.text
    }

    init {
        background = Theme.palette.bg
        border = Widgets.pad(4)
        add(Widgets.title("Журнал").also { it.border = Widgets.pad(1) }, BorderLayout.NORTH)
        add(JScrollPane(area), BorderLayout.CENTER)
        add(
            JPanel(FlowLayout(FlowLayout.LEFT, Widgets.STEP * 2, Widgets.STEP * 2)).apply {
                isOpaque = false
                add(Widgets.button("Обновить") { reload() })
                add(
                    Widgets.button("Копировать журнал") {
                        reload()
                        Toolkit.getDefaultToolkit().systemClipboard.setContents(StringSelection(area.text), null)
                    },
                )
            },
            BorderLayout.SOUTH,
        )
    }

    fun reload() {
        area.text = graph.log.snapshot().joinToString("\n") { it.render() }
        area.caretPosition = area.document.length
    }

    private companion object {
        const val MONO_SIZE = 12
    }
}
