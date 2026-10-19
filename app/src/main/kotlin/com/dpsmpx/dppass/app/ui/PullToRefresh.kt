package com.dpsmpx.dppass.app.ui

import android.animation.ObjectAnimator
import android.animation.ValueAnimator
import android.annotation.SuppressLint
import android.content.Context
import android.content.res.ColorStateList
import android.view.Gravity
import android.view.HapticFeedbackConstants
import android.view.MotionEvent
import android.view.View
import android.view.ViewConfiguration
import android.view.animation.LinearInterpolator
import android.widget.FrameLayout
import android.widget.ImageView
import com.dpsmpx.dppass.R

/**
 * Протяжка вниз над прокручиваемым [content] (D-70): как обновление
 * страницы в браузере — список в самом верху, палец тянет вниз, сверху
 * опускается значок; отпустил за порогом — [onRefresh]. Свой жест: AndroidX
 * в приложении нет, а `SwipeRefreshLayout` — из него.
 *
 * Жест — не единственный путь: у того же действия есть кнопка, её видит
 * TalkBack, а протяжку им не сделать. [onRefresh] отвечает, начато ли
 * дело; начато — значок крутится до [finish], нет — сразу уходит.
 *
 * Перехват — только когда [content] уже в самом верху и палец пошёл вниз
 * дальше порога касания: обычная прокрутка и прокрутка вверх не задеты.
 */
// Создаётся только из кода экрана (D-34): конструктора для разметки XML не нужно.
@SuppressLint("ViewConstructor")
class PullToRefresh(
    context: Context,
    private val content: View,
    private val onRefresh: () -> Boolean,
) : FrameLayout(context) {
    private val slop = ViewConfiguration.get(context).scaledTouchSlop
    private val size = Ui.dp(context, SIZE_DP)
    private val gesture = PullGesture(Ui.dpF(context, THRESHOLD_DP), Ui.dpF(context, MAX_DP))
    private val icon = ImageView(context).apply {
        setImageResource(R.drawable.ic_refresh)
        imageTintList = ColorStateList.valueOf(context.getColor(R.color.on_primary_container))
    }
    private val indicator = FrameLayout(context).apply {
        setBackgroundResource(R.drawable.bg_oval)
        backgroundTintList = ColorStateList.valueOf(context.getColor(R.color.primary_container))
        elevation = Ui.dpF(context, 3f)
        // Украшение: с TalkBack протяжку не сделать, у действия есть кнопка.
        importantForAccessibility = View.IMPORTANT_FOR_ACCESSIBILITY_NO
        addView(icon, LayoutParams(Ui.dp(context, 24), Ui.dp(context, 24), Gravity.CENTER))
        translationY = -size.toFloat()
        alpha = 0f
    }
    private var startY = 0f
    private var pulling = false
    private var wasArmed = false
    private var spin: ValueAnimator? = null

    /** Идёт ли начатое протяжкой дело: значок крутится, новая протяжка не начинается. */
    var refreshing: Boolean = false
        private set

    init {
        addView(content, LayoutParams(LayoutParams.MATCH_PARENT, LayoutParams.MATCH_PARENT))
        addView(indicator, LayoutParams(size, size, Gravity.TOP or Gravity.CENTER_HORIZONTAL))
    }

    override fun onInterceptTouchEvent(ev: MotionEvent): Boolean {
        if (refreshing || !isEnabled) return false
        when (ev.actionMasked) {
            MotionEvent.ACTION_DOWN -> {
                startY = ev.y
                pulling = false
            }
            MotionEvent.ACTION_MOVE ->
                if (!pulling && ev.y - startY > slop && !content.canScrollVertically(-1)) {
                    pulling = true
                    wasArmed = false
                    startY += slop
                }
        }
        return pulling
    }

    // Нажатия (performClick) здесь нет — только протяжка; у действия есть кнопка для TalkBack.
    @SuppressLint("ClickableViewAccessibility")
    override fun onTouchEvent(ev: MotionEvent): Boolean {
        if (!pulling) return super.onTouchEvent(ev)
        when (ev.actionMasked) {
            MotionEvent.ACTION_MOVE -> {
                gesture.drag(ev.y - startY)
                if (gesture.armed && !wasArmed) performHapticFeedback(HapticFeedbackConstants.CONTEXT_CLICK)
                wasArmed = gesture.armed
                follow()
            }
            MotionEvent.ACTION_UP -> {
                pulling = false
                if (gesture.release() && onRefresh()) start() else hide()
            }
            MotionEvent.ACTION_CANCEL -> {
                pulling = false
                gesture.cancel()
                hide()
            }
        }
        return true
    }

    /** Дело, начатое протяжкой, закончено: значок уходит. */
    fun finish() {
        if (!refreshing) return
        refreshing = false
        spin?.cancel()
        spin = null
        hide()
    }

    // Экран закрыли посреди замера: бесконечный поворот не должен жить без окна.
    override fun onDetachedFromWindow() {
        finish()
        super.onDetachedFromWindow()
    }

    private fun follow() {
        indicator.animate().cancel()
        indicator.translationY = gesture.offset - size
        indicator.alpha = gesture.progress
        icon.rotation = gesture.progress * TURN_DEGREES
    }

    private fun start() {
        refreshing = true
        indicator.animate().translationY(Ui.dpF(context, THRESHOLD_DP) - size).alpha(1f).setDuration(SETTLE_MILLIS).start()
        spin = ObjectAnimator.ofFloat(icon, View.ROTATION, icon.rotation, icon.rotation + 360f).apply {
            duration = SPIN_MILLIS
            repeatCount = ValueAnimator.INFINITE
            interpolator = LinearInterpolator()
            start()
        }
    }

    private fun hide() {
        indicator.animate().translationY(-size.toFloat()).alpha(0f).setDuration(SETTLE_MILLIS).start()
    }

    private companion object {
        const val SIZE_DP = 40
        const val THRESHOLD_DP = 72f
        const val MAX_DP = 120f
        const val TURN_DEGREES = 270f
        const val SETTLE_MILLIS = 180L
        const val SPIN_MILLIS = 900L
    }
}
