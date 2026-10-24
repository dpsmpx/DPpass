package com.dpsmpx.dppass.app.device

import android.app.Activity
import android.app.Instrumentation
import android.content.Context
import android.content.Intent
import android.os.SystemClock
import android.view.KeyEvent
import android.view.MotionEvent
import android.view.View
import android.view.ViewGroup
import android.widget.TextView
import com.dpsmpx.dppass.R
import com.dpsmpx.dppass.app.MainActivity

/**
 * Руки и глаза тестов на телефоне (D-75): запуск экрана, обход видов,
 * ожидание, жесты. Тесты только смотрят: нажимать можно только то, что
 * ведёт по экранам ([tap]), — это держит `check_device_tests.py`.
 *
 * Те же тесты идут на JVM под Robolectric (D-86); где телефон и JVM
 * расходятся — время, касания, «Назад», открыт ли лист, — действуют
 * [Hands].
 */
class Device(private val instrumentation: Instrumentation, private val hands: Hands = PhoneHands(instrumentation)) {
    val context: Context = instrumentation.targetContext
    private val opened = mutableListOf<Activity>()

    /** Подписи, нажимать которые тестам можно: вкладки, «Добавить», «Назад» — переходы, а не действия. */
    private val navigation: Set<String> = listOf(
        R.string.tab_connect,
        R.string.tab_servers,
        R.string.tab_subscriptions,
        R.string.tab_settings,
        R.string.add_title,
        R.string.action_back,
    ).map(context::getString).toSet()

    fun launch(): Activity {
        val intent = Intent(context, MainActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TASK)
        val activity = instrumentation.startActivitySync(intent)
        opened += activity
        idle()
        return activity
    }

    /** После теста: открытые им экраны — закрыть. */
    fun close() {
        opened.forEach { a -> main { a.finish() } }
        opened.clear()
        idle()
    }

    fun idle() = instrumentation.waitForIdleSync()

    /** [block] на главном потоке; исключение — тесту, как есть. */
    fun <T> main(block: () -> T): T {
        var out: Result<T>? = null
        instrumentation.runOnMainSync { out = runCatching(block) }
        return checkNotNull(out).getOrThrow()
    }

    /** Ждать [condition] (на главном потоке) не дольше [timeoutMillis]; не дождался — отказ теста с [what]. */
    fun waitUntil(what: String, timeoutMillis: Long = 5_000, condition: () -> Boolean) {
        val deadline = hands.now() + timeoutMillis
        while (!main(condition)) {
            if (hands.now() > deadline) throw AssertionError("за $timeoutMillis мс не дождался: $what")
            hands.pause(POLL_MILLIS)
        }
    }

    /** Видимые виды экрана, в порядке обхода. */
    fun views(activity: Activity): List<View> = main { buildList { collect(activity.window.decorView, this) } }

    private fun collect(v: View, out: MutableList<View>) {
        if (!v.isShown) return
        out += v
        if (v is ViewGroup) for (i in 0 until v.childCount) collect(v.getChildAt(i), out)
    }

    /** Что прочтёт TalkBack: описание, текст, подсказка поля — или тексты внутри строки. */
    fun label(v: View): String = main {
        own(v) ?: (v as? ViewGroup)?.let { g -> buildList { texts(g, this) }.joinToString(" ").ifBlank { null } } ?: ""
    }

    private fun own(v: View): String? = v.contentDescription?.toString()?.takeIf { it.isNotBlank() }
        ?: (v as? TextView)?.let { t -> t.text?.toString()?.takeIf { it.isNotBlank() } ?: t.hint?.toString()?.takeIf { it.isNotBlank() } }

    private fun texts(g: ViewGroup, out: MutableList<String>) {
        for (i in 0 until g.childCount) {
            val c = g.getChildAt(i)
            if (!c.isShown || c.importantForAccessibility == View.IMPORTANT_FOR_ACCESSIBILITY_NO_HIDE_DESCENDANTS) continue
            own(c)?.let { out += it }
            if (c is ViewGroup) texts(c, out)
        }
    }

    /**
     * Нажимаемый вид с подписью [text] (описание или текст), видимый сейчас.
     * Только нажимаемый: у вкладки и заголовка её экрана одна подпись.
     */
    fun find(activity: Activity, text: String): View? = views(activity).firstOrNull { v ->
        main { v.isClickable && (v.contentDescription?.toString() == text || (v as? TextView)?.text?.toString() == text) }
    }

    /** Нажать переход по экранам — и только его: тесты не меняют данные приложения (D-75). */
    fun tap(activity: Activity, label: String) {
        check(label in navigation) { "тест нажимает «$label» — нажимать можно только переходы: $navigation" }
        val v = checkNotNull(find(activity, label)) { "нет «$label» на экране" }
        main { v.performClick() }
        idle()
    }

    fun back() {
        hands.back()
        idle()
    }

    /** Открыт ли поверх экрана [activity] лист (диалог). */
    fun sheetShown(activity: Activity): Boolean = main { hands.sheetShown(activity) }

    /**
     * Провести пальцем по [view] по вертикали (пиксели от верха вида): от
     * [fromY] до [toY], там — [atTurn] (палец ещё на экране), затем до
     * [thenY] и отпустить.
     */
    fun drag(view: View, fromY: Float, toY: Float, thenY: Float = toY, atTurn: () -> Unit = {}) {
        val (x, top) = main {
            val at = IntArray(2)
            view.getLocationOnScreen(at)
            (at[0] + view.width / 2f) to at[1].toFloat()
        }
        val down = SystemClock.uptimeMillis()
        var t = down
        fun send(action: Int, y: Float) {
            val e = MotionEvent.obtain(down, t, action, x, top + y, 0)
            hands.pointer(view, e)
            e.recycle()
            t += STEP_MILLIS
        }

        // Мелкими шагами, как палец: жест узнаёт протяжку по порогу касания.
        fun move(from: Float, to: Float) {
            val steps = (kotlin.math.abs(to - from) / dp(STEP_DP)).toInt().coerceAtLeast(1)
            for (i in 1..steps) send(MotionEvent.ACTION_MOVE, from + (to - from) * i / steps)
        }
        send(MotionEvent.ACTION_DOWN, fromY)
        move(fromY, toY)
        idle()
        atTurn()
        move(toY, thenY)
        send(MotionEvent.ACTION_UP, thenY)
        idle()
    }

    fun dp(value: Float): Float = value * context.resources.displayMetrics.density

    /** Где телефон и JVM (Robolectric) расходятся: время, касание, «Назад», открыт ли лист. */
    interface Hands {
        fun now(): Long

        fun pause(millis: Long)

        fun pointer(view: View, event: MotionEvent)

        fun back()

        fun sheetShown(activity: Activity): Boolean
    }

    /** Телефон: часы системы, касания и «Назад» — системой ввода, лист — отдельное окно, у экрана нет фокуса. */
    class PhoneHands(private val instrumentation: Instrumentation) : Hands {
        override fun now(): Long = SystemClock.uptimeMillis()

        // Тест ждёт приложение на телефоне — по-другому только опрос (правило blocking — для src/main).
        override fun pause(millis: Long) = SystemClock.sleep(millis)

        override fun pointer(view: View, event: MotionEvent) = instrumentation.sendPointerSync(event)

        override fun back() = instrumentation.sendKeyDownUpSync(KeyEvent.KEYCODE_BACK)

        override fun sheetShown(activity: Activity): Boolean = !activity.hasWindowFocus()
    }

    private companion object {
        const val POLL_MILLIS = 50L
        const val STEP_MILLIS = 16L
        const val STEP_DP = 8f
    }
}
