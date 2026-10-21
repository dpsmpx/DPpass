package com.dpsmpx.dppass.desktop.ui

import com.dpsmpx.dppass.diagnostics.Diagnostic
import java.awt.BasicStroke
import java.awt.BorderLayout
import java.awt.Color
import java.awt.Cursor
import java.awt.Dimension
import java.awt.Font
import java.awt.Graphics
import java.awt.Graphics2D
import java.awt.RenderingHints
import java.awt.event.MouseAdapter
import java.awt.event.MouseEvent
import javax.swing.BorderFactory
import javax.swing.JButton
import javax.swing.JComponent
import javax.swing.JLabel
import javax.swing.JPanel
import javax.swing.JTextArea
import javax.swing.border.Border

/** Общие элементы окна: отступы по шагу 4 (D-34), текст, плашки, круглая кнопка. */
object Widgets {
    const val STEP: Int = 4

    fun pad(n: Int): Border = BorderFactory.createEmptyBorder(n * STEP, n * STEP, n * STEP, n * STEP)

    fun title(text: String): JLabel = JLabel(text).apply {
        font = font.deriveFont(Font.BOLD, TITLE_SIZE)
        foreground = Theme.palette.text
    }

    fun caption(text: String = ""): JLabel = JLabel(text).apply { foreground = Theme.palette.textSecondary }

    fun button(text: String, action: () -> Unit): JButton = JButton(text).apply { addActionListener { action() } }

    /** Многострочный текст только для чтения — переносится по словам, выделяется и копируется. */
    fun note(): JTextArea = JTextArea().apply {
        isEditable = false
        lineWrap = true
        wrapStyleWord = true
        isOpaque = false
        foreground = Theme.palette.text
        border = null
    }

    /** Плашка предупреждения или ошибки — с текстом, который можно выделить. */
    class Banner(error: Boolean) : JPanel(BorderLayout()) {
        private val text = note()

        init {
            val p = Theme.palette
            background = if (error) p.errorContainer else p.warningContainer
            text.foreground = p.text
            border = BorderFactory.createCompoundBorder(BorderFactory.createLineBorder(if (error) p.error else p.warning), pad(3))
            add(text)
            isVisible = false
        }

        fun show(message: String?) {
            text.text = message.orEmpty()
            isVisible = !message.isNullOrBlank()
        }
    }

    /** Текст диагностики с причинами (D-22) — как в журнале, без секретов: их уже убрал Redactor. */
    fun describe(d: Diagnostic): String = buildString {
        append(d.message)
        val causes = d.renderWithCauses().drop(1)
        if (causes.isNotEmpty()) append("\n\n").append(causes.joinToString("\n") { it.trim() })
    }

    private const val TITLE_SIZE = 20f
}

/** Круглая кнопка питания: цвет — состояние туннеля; нажатие — подключить или отключить. */
class PowerButton(private val onClick: () -> Unit) : JComponent() {
    var fill: Color = Theme.palette.surfaceVariant
        set(value) {
            field = value
            repaint()
        }
    var ring: Color = Theme.palette.outline
        set(value) {
            field = value
            repaint()
        }

    init {
        preferredSize = Dimension(SIZE, SIZE)
        // Колонка BoxLayout растянула бы кнопку на всё место.
        maximumSize = preferredSize
        minimumSize = preferredSize
        cursor = Cursor.getPredefinedCursor(Cursor.HAND_CURSOR)
        isFocusable = true
        toolTipText = "Подключить или отключить"
        addMouseListener(
            object : MouseAdapter() {
                override fun mouseClicked(e: MouseEvent) {
                    if (isEnabled) onClick()
                }
            },
        )
        addKeyListener(
            object : java.awt.event.KeyAdapter() {
                override fun keyPressed(e: java.awt.event.KeyEvent) {
                    if (isEnabled && (e.keyCode == java.awt.event.KeyEvent.VK_SPACE || e.keyCode == java.awt.event.KeyEvent.VK_ENTER)) onClick()
                }
            },
        )
    }

    override fun paintComponent(g: Graphics) {
        val g2 = g.create() as Graphics2D
        try {
            g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON)
            val d = minOf(width, height) - MARGIN * 2
            val x = (width - d) / 2
            val y = (height - d) / 2
            g2.color = fill
            g2.fillOval(x, y, d, d)
            g2.color = ring
            g2.stroke = BasicStroke(RING)
            g2.drawOval(x, y, d, d)
            // Значок питания: дуга и черта — свой рисунок (D-01).
            val icon = d / 3
            val cx = width / 2
            val cy = height / 2
            g2.stroke = BasicStroke(ICON_STROKE, BasicStroke.CAP_ROUND, BasicStroke.JOIN_ROUND)
            g2.color = Theme.palette.text
            g2.drawArc(cx - icon / 2, cy - icon / 2, icon, icon, ARC_START, ARC_EXTENT)
            g2.drawLine(cx, cy - icon / 2 - ICON_STROKE.toInt(), cx, cy)
            if (isFocusOwner) {
                g2.color = Theme.palette.primary
                g2.stroke = BasicStroke(1f)
                g2.drawOval(x - 3, y - 3, d + 6, d + 6)
            }
        } finally {
            g2.dispose()
        }
    }

    private companion object {
        const val SIZE = 168
        const val MARGIN = 8
        const val RING = 3f
        const val ICON_STROKE = 6f
        const val ARC_START = 120
        const val ARC_EXTENT = 300
    }
}
