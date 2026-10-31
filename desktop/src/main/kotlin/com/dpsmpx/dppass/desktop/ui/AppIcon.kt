package com.dpsmpx.dppass.desktop.ui

import java.awt.BasicStroke
import java.awt.Color
import java.awt.RenderingHints
import java.awt.geom.Arc2D
import java.awt.geom.Ellipse2D
import java.awt.geom.Line2D
import java.awt.image.BufferedImage
import kotlin.math.atan2
import kotlin.math.sqrt

/**
 * Значок DPpass (D-01) — рисунок `desktop/package/dppass.svg`: кнопка
 * питания в цветах системы дизайна (D-34). SVG JDK не читает, поэтому тот
 * же рисунок — Java2D в координатах SVG (128 × 128): окно и значок в
 * области уведомлений Windows (D-97). Значок `dppass.exe` рисует из того же
 * SVG `tools/desktop/windows_package.py`.
 */
object AppIcon {
    /** Размеры для окна: система берёт ближайший к нужному. */
    val SIZES: List<Int> = listOf(16, 24, 32, 48, 64, 128)

    private const val VIEW = 128.0
    private val FILL = Color(0x213875)
    private val RING = Color(0x92B1FF)
    private val MARK = Color(0xECEEF3)

    fun image(size: Int): BufferedImage {
        require(size > 0) { "размер значка — больше нуля" }
        val img = BufferedImage(size, size, BufferedImage.TYPE_INT_ARGB)
        val g = img.createGraphics()
        try {
            g.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON)
            g.setRenderingHint(RenderingHints.KEY_STROKE_CONTROL, RenderingHints.VALUE_STROKE_PURE)
            g.scale(size / VIEW, size / VIEW)
            // <circle cx="64" cy="64" r="58" stroke-width="6">
            val circle = Ellipse2D.Double(64.0 - 58, 64.0 - 58, 116.0, 116.0)
            g.color = FILL
            g.fill(circle)
            g.color = RING
            g.stroke = BasicStroke(6f)
            g.draw(circle)
            // <path d="M44 42 A30 30 0 1 0 84 42">: большая дуга через низ; центр — на оси x = 64.
            g.color = MARK
            g.stroke = BasicStroke(9f, BasicStroke.CAP_ROUND, BasicStroke.JOIN_ROUND)
            val r = 30.0
            val cy = 42.0 + sqrt(r * r - 20.0 * 20.0)
            val start = Math.toDegrees(atan2(cy - 42.0, 44.0 - 64.0))
            val end = Math.toDegrees(atan2(cy - 42.0, 84.0 - 64.0))
            g.draw(Arc2D.Double(64.0 - r, cy - r, 2 * r, 2 * r, start, 360.0 - (start - end), Arc2D.OPEN))
            // <line x1="64" y1="28" x2="64" y2="62">
            g.draw(Line2D.Double(64.0, 28.0, 64.0, 62.0))
        } finally {
            g.dispose()
        }
        return img
    }
}
