package com.dpsmpx.dppass.app.ui

import android.content.Context
import android.graphics.Canvas
import android.graphics.Paint
import android.graphics.Rect
import android.graphics.Typeface
import android.os.Build
import android.os.Bundle
import android.text.TextPaint
import android.text.TextUtils
import android.util.TypedValue
import android.view.GestureDetector
import android.view.MotionEvent
import android.view.View
import android.view.accessibility.AccessibilityEvent
import android.view.accessibility.AccessibilityNodeInfo
import android.view.accessibility.AccessibilityNodeProvider
import android.widget.OverScroller
import com.dpsmpx.dppass.R
import kotlin.math.max
import kotlin.math.min
import kotlin.math.roundToInt

/**
 * Таблица анализатора соединений (D-106) — строго по столбцам, как в
 * диспетчере задач и `top`: закреплены заголовок и первый столбец,
 * прокрутка по обеим осям, ширина столбца — по образцу значения, а не по
 * текущим данным (числа не прыгают при обновлении), цифры одной ширины.
 * Нажатие на заголовок — сортировка ([onHeader]), на строку — подробности
 * ([onRow]). Рисуется на холсте: тысячи ячеек раз в секунду отдельными
 * `TextView` не обновить.
 *
 * TalkBack видит заголовки и видимые строки как отдельные элементы
 * (виртуальные узлы): у строки — описание из модели, нажатие — то же, что
 * пальцем.
 */
class GridTable(context: Context) : View(context) {
    /** Столбец: заголовок, образец самого широкого значения, число ли (вправо). */
    class Column(val title: String, val sample: String, val numeric: Boolean)

    interface Model {
        val columns: List<Column>
        val rows: Int

        /** Сортировка: номер столбца (-1 — нет) и направление — стрелка в заголовке. */
        val sortColumn: Int
        val sortDescending: Boolean

        fun text(row: Int, col: Int): String

        /** Цвет текста ячейки. */
        fun color(row: Int, col: Int): Int

        /** Фон ячейки (подсветка величины); 0 — нет. */
        fun background(row: Int, col: Int): Int

        /** Полоса слева у строки — состояние; 0 — нет. */
        fun stripe(row: Int): Int

        /** Строка для TalkBack. */
        fun describe(row: Int): String
    }

    var model: Model? = null
        set(value) {
            val columnsChanged = field?.columns != value?.columns
            field = value
            if (columnsChanged) widths = IntArray(0)
            clamp()
            invalidate()
        }

    var onHeader: ((Int) -> Unit)? = null
    var onRow: ((Int) -> Unit)? = null

    private fun sp(v: Float) = TypedValue.applyDimension(TypedValue.COMPLEX_UNIT_SP, v, resources.displayMetrics)

    private val cellPaint = TextPaint(Paint.ANTI_ALIAS_FLAG).apply {
        textSize = sp(13f)
        fontFeatureSettings = "tnum"
    }
    private val headPaint = TextPaint(Paint.ANTI_ALIAS_FLAG).apply {
        textSize = sp(12f)
        typeface = Typeface.create(Typeface.DEFAULT, Typeface.BOLD)
        fontFeatureSettings = "tnum"
        color = context.getColor(R.color.text_secondary)
    }
    private val fill = Paint()
    private val rowHeight = Ui.dp(context, 36)
    private val headHeight = Ui.dp(context, 40)
    private val pad = Ui.dp(context, 8)
    private val stripeWidth = Ui.dp(context, 3)
    private val line = maxOf(1, Ui.dp(context, 1) / 2)
    private val surface = context.getColor(R.color.surface)
    private val headBg = context.getColor(R.color.surface_variant)
    private val outline = context.getColor(R.color.outline)

    private var widths = IntArray(0)
    private var offX = 0
    private var offY = 0
    private val scroller = OverScroller(context)

    private fun measureColumns(m: Model) {
        if (widths.size == m.columns.size) return
        widths = IntArray(m.columns.size) { i ->
            val c = m.columns[i]
            val head = headPaint.measureText(c.title + ARROW)
            val body = cellPaint.measureText(c.sample)
            max(head, body).roundToInt() + 2 * pad + if (i == 0) stripeWidth else 0
        }
    }

    private val contentWidth: Int get() = widths.sum()
    private val maxX: Int get() = max(0, contentWidth - width)
    private val maxY: Int get() = max(0, (model?.rows ?: 0) * rowHeight - (height - headHeight))

    private fun clamp() {
        offX = offX.coerceIn(0, maxX)
        offY = offY.coerceIn(0, maxY)
    }

    override fun onSizeChanged(w: Int, h: Int, oldw: Int, oldh: Int) {
        clamp()
    }

    /** Левый край столбца [col] на экране: первый закреплён. */
    private fun left(col: Int): Int {
        var x = 0
        for (i in 0 until col) x += widths[i]
        return if (col == 0) 0 else x - offX
    }

    override fun onDraw(canvas: Canvas) {
        val m = model ?: return
        measureColumns(m)
        clamp()
        canvas.drawColor(surface)
        val first = offY / rowHeight
        val last = min(m.rows - 1, (offY + height - headHeight) / rowHeight)
        val pinned = widths.firstOrNull() ?: return
        // Сначала прокручиваемые столбцы, поверх — закреплённый первый.
        canvas.save()
        canvas.clipRect(pinned, headHeight, width, height)
        for (r in first..last) drawRow(canvas, m, r, 1 until m.columns.size)
        canvas.restore()
        canvas.save()
        canvas.clipRect(0, headHeight, pinned, height)
        for (r in first..last) drawRow(canvas, m, r, 0 until 1)
        canvas.restore()
        fill.color = outline
        canvas.drawRect(pinned.toFloat() - line, headHeight.toFloat(), pinned.toFloat(), height.toFloat(), fill)
        drawHeader(canvas, m)
    }

    private fun drawRow(canvas: Canvas, m: Model, r: Int, cols: IntRange) {
        val top = headHeight + r * rowHeight - offY
        for (c in cols) {
            val x = left(c)
            val w = widths[c]
            if (x + w < 0 || x > width) continue
            val bg = m.background(r, c)
            fill.color = if (bg != 0) bg else surface
            canvas.drawRect(x.toFloat(), top.toFloat(), (x + w).toFloat(), (top + rowHeight).toFloat(), fill)
            val inset = if (c == 0) stripeWidth else 0
            if (c == 0) {
                val s = m.stripe(r)
                if (s != 0) {
                    fill.color = s
                    canvas.drawRect(x.toFloat(), top.toFloat(), (x + stripeWidth).toFloat(), (top + rowHeight).toFloat(), fill)
                }
            }
            cellPaint.color = m.color(r, c)
            drawText(canvas, cellPaint, m.text(r, c), x + inset, w - inset, top, rowHeight, m.columns[c].numeric)
        }
        fill.color = outline
        canvas.drawRect(0f, (top + rowHeight - line).toFloat(), width.toFloat(), (top + rowHeight).toFloat(), fill)
    }

    private fun drawHeader(canvas: Canvas, m: Model) {
        fill.color = headBg
        canvas.drawRect(0f, 0f, width.toFloat(), headHeight.toFloat(), fill)
        for (c in m.columns.indices.reversed()) {
            val x = left(c)
            if (c != 0 && x + widths[c] < widths[0]) continue
            if (c == 0) {
                fill.color = headBg
                canvas.drawRect(0f, 0f, widths[0].toFloat(), headHeight.toFloat(), fill)
            }
            canvas.save()
            if (c != 0) canvas.clipRect(widths[0], 0, width, headHeight)
            val title = m.columns[c].title + if (c == m.sortColumn) (if (m.sortDescending) " ▼" else " ▲") else ""
            headPaint.color = context.getColor(if (c == m.sortColumn) R.color.primary else R.color.text_secondary)
            drawText(canvas, headPaint, title, x + if (c == 0) stripeWidth else 0, widths[c], 0, headHeight, m.columns[c].numeric)
            canvas.restore()
        }
        fill.color = outline
        canvas.drawRect(0f, (headHeight - line).toFloat(), width.toFloat(), headHeight.toFloat(), fill)
    }

    private fun drawText(canvas: Canvas, paint: TextPaint, text: String, x: Int, w: Int, top: Int, h: Int, right: Boolean) {
        val avail = (w - 2 * pad).toFloat()
        val shown = TextUtils.ellipsize(text, paint, avail, TextUtils.TruncateAt.END).toString()
        val tx = if (right) x + w - pad - paint.measureText(shown) else (x + pad).toFloat()
        val ty = top + h / 2f - (paint.descent() + paint.ascent()) / 2f
        canvas.drawText(shown, tx, ty, paint)
    }

    // ---- касания ----

    private val gestures = GestureDetector(
        context,
        object : GestureDetector.SimpleOnGestureListener() {
            override fun onDown(e: MotionEvent): Boolean {
                scroller.forceFinished(true)
                return true
            }

            override fun onScroll(e1: MotionEvent?, e2: MotionEvent, dx: Float, dy: Float): Boolean {
                parent?.requestDisallowInterceptTouchEvent(true)
                scrollTo(offX + dx.roundToInt(), offY + dy.roundToInt())
                return true
            }

            override fun onFling(e1: MotionEvent?, e2: MotionEvent, vx: Float, vy: Float): Boolean {
                scroller.fling(offX, offY, -vx.roundToInt(), -vy.roundToInt(), 0, maxX, 0, maxY)
                postInvalidateOnAnimation()
                return true
            }

            override fun onSingleTapUp(e: MotionEvent): Boolean {
                tap(e.x.roundToInt(), e.y.roundToInt())
                return true
            }
        },
    )

    override fun onTouchEvent(event: MotionEvent): Boolean {
        val handled = gestures.onTouchEvent(event)
        if (event.actionMasked == MotionEvent.ACTION_UP) performClick()
        return handled || super.onTouchEvent(event)
    }

    // Нажатие обрабатывает жест (столбец или строка); здесь — только для доступности.
    override fun performClick(): Boolean = super.performClick()

    override fun scrollTo(x: Int, y: Int) {
        offX = x
        offY = y
        clamp()
        invalidate()
    }

    override fun computeScroll() {
        if (scroller.computeScrollOffset()) {
            scrollTo(scroller.currX, scroller.currY)
            postInvalidateOnAnimation()
        }
    }

    private fun columnAt(x: Int): Int {
        if (widths.isEmpty()) return -1
        if (x < widths[0]) return 0
        var acc = 0
        for (i in widths.indices) {
            val l = if (i == 0) 0 else acc - offX
            if (i > 0 && x >= l && x < l + widths[i]) return i
            acc += widths[i]
        }
        return -1
    }

    private fun rowAt(y: Int): Int {
        val m = model ?: return -1
        if (y < headHeight) return -1
        val r = (y - headHeight + offY) / rowHeight
        return if (r in 0 until m.rows) r else -1
    }

    private fun tap(x: Int, y: Int) {
        if (y < headHeight) {
            columnAt(x).takeIf { it >= 0 }?.let { onHeader?.invoke(it) }
        } else {
            rowAt(y).takeIf { it >= 0 }?.let { onRow?.invoke(it) }
        }
    }

    /** Видимые строки (для проверки и TalkBack). */
    fun visibleRows(): IntRange {
        val m = model ?: return IntRange.EMPTY
        if (m.rows == 0) return IntRange.EMPTY
        return (offY / rowHeight)..min(m.rows - 1, (offY + max(0, height - headHeight)) / rowHeight)
    }

    // ---- доступность: заголовки и видимые строки — виртуальные узлы ----

    private var focused = NONE

    override fun getAccessibilityNodeProvider(): AccessibilityNodeProvider = provider

    override fun dispatchHoverEvent(event: MotionEvent): Boolean {
        val id = idAt(event.x.roundToInt(), event.y.roundToInt())
        if (id != NONE && event.actionMasked != MotionEvent.ACTION_HOVER_EXIT) {
            send(id, AccessibilityEvent.TYPE_VIEW_HOVER_ENTER)
            return true
        }
        return super.dispatchHoverEvent(event)
    }

    private fun idAt(x: Int, y: Int): Int {
        if (y < headHeight) return columnAt(x).takeIf { it >= 0 }?.let { HEADER + it } ?: NONE
        return rowAt(y).takeIf { it >= 0 }?.let { ROW + it } ?: NONE
    }

    private fun bounds(id: Int): Rect? {
        val m = model ?: return null
        return when {
            id >= ROW -> {
                val r = id - ROW
                if (r >= m.rows) return null
                val top = headHeight + r * rowHeight - offY
                Rect(0, top, width, top + rowHeight)
            }
            id >= HEADER -> {
                val c = id - HEADER
                if (c >= widths.size) return null
                val l = left(c)
                Rect(max(l, if (c == 0) 0 else widths[0]), 0, min(width, l + widths[c]), headHeight)
            }
            else -> null
        }
    }

    private fun send(id: Int, type: Int) {
        if (parent == null) return
        val e = newEvent(type)
        e.packageName = context.packageName
        e.setSource(this, id)
        e.text.add(label(id))
        parent.requestSendAccessibilityEvent(this, e)
    }

    private fun label(id: Int): String {
        val m = model ?: return ""
        return if (id >= ROW) m.describe(id - ROW) else m.columns[id - HEADER].title
    }

    private val provider = object : AccessibilityNodeProvider() {
        override fun createAccessibilityNodeInfo(virtualViewId: Int): AccessibilityNodeInfo? {
            if (virtualViewId == AccessibilityNodeProvider.HOST_VIEW_ID) {
                val info = newNode()
                onInitializeAccessibilityNodeInfo(info)
                info.className = GridTable::class.java.name
                widths.indices.forEach { info.addChild(this@GridTable, HEADER + it) }
                visibleRows().forEach { info.addChild(this@GridTable, ROW + it) }
                return info
            }
            val rect = bounds(virtualViewId) ?: return null
            val info = newNode()
            info.setSource(this@GridTable, virtualViewId)
            info.setParent(this@GridTable)
            info.packageName = context.packageName
            info.className = if (virtualViewId >= ROW) "android.widget.TextView" else "android.widget.Button"
            info.text = label(virtualViewId)
            val loc = IntArray(2)
            getLocationOnScreen(loc)
            info.setBoundsInScreen(Rect(rect).apply { offset(loc[0], loc[1]) })
            info.isVisibleToUser = !rect.isEmpty
            info.isEnabled = true
            info.isClickable = true
            info.addAction(AccessibilityNodeInfo.AccessibilityAction.ACTION_CLICK)
            if (focused == virtualViewId) {
                info.isAccessibilityFocused = true
                info.addAction(AccessibilityNodeInfo.AccessibilityAction.ACTION_CLEAR_ACCESSIBILITY_FOCUS)
            } else {
                info.addAction(AccessibilityNodeInfo.AccessibilityAction.ACTION_ACCESSIBILITY_FOCUS)
            }
            return info
        }

        override fun performAction(virtualViewId: Int, action: Int, arguments: Bundle?): Boolean {
            if (virtualViewId == AccessibilityNodeProvider.HOST_VIEW_ID) return performAccessibilityAction(action, arguments)
            return when (action) {
                AccessibilityNodeInfo.ACTION_CLICK -> {
                    if (virtualViewId >= ROW) onRow?.invoke(virtualViewId - ROW) else onHeader?.invoke(virtualViewId - HEADER)
                    send(virtualViewId, AccessibilityEvent.TYPE_VIEW_CLICKED)
                    true
                }
                AccessibilityNodeInfo.ACTION_ACCESSIBILITY_FOCUS -> {
                    focused = virtualViewId
                    send(virtualViewId, AccessibilityEvent.TYPE_VIEW_ACCESSIBILITY_FOCUSED)
                    true
                }
                AccessibilityNodeInfo.ACTION_CLEAR_ACCESSIBILITY_FOCUS -> {
                    if (focused == virtualViewId) focused = NONE
                    send(virtualViewId, AccessibilityEvent.TYPE_VIEW_ACCESSIBILITY_FOCUS_CLEARED)
                    true
                }
                else -> false
            }
        }
    }

    private companion object {
        const val ARROW = " ▼"
        const val NONE = Int.MIN_VALUE
        const val HEADER = 1
        const val ROW = 1_000

        fun newNode(): AccessibilityNodeInfo = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            AccessibilityNodeInfo()
        } else {
            @Suppress("DEPRECATION") // конструктор узла — только с API 30
            AccessibilityNodeInfo.obtain()
        }

        fun newEvent(type: Int): AccessibilityEvent = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            AccessibilityEvent(type)
        } else {
            @Suppress("DEPRECATION") // конструктор события — только с API 30
            AccessibilityEvent.obtain(type)
        }
    }
}
