package com.dpsmpx.dppass.app.ui

import android.annotation.SuppressLint
import android.content.Context
import android.os.Build
import android.view.Gravity
import android.view.HapticFeedbackConstants
import android.view.Surface
import android.view.SurfaceHolder
import android.view.SurfaceView
import android.view.View
import android.widget.FrameLayout
import android.widget.LinearLayout
import com.dpsmpx.dppass.R
import com.dpsmpx.dppass.app.TunnelStatus

/**
 * «QR-код камерой» (D-71): превью и подсказка. Камера открыта, только пока
 * экран виден ([onShown] … [onHidden]) и есть поверхность превью. Первый
 * найденный код закрывает экран и идёт тем же путём, что буфер обмена
 * (D-42): распознавание, сводка, подтверждение (T13).
 */
class QrCameraScreen internal constructor(host: Host, private val choice: QrCamera.Choice) : SubScreen(host, R.string.qr_camera_title) {
    override val scrolls: Boolean = false

    private var shown = false
    private var surfaceReady = false
    private var finished = false
    private val camera = QrCamera(context, choice, ::found, ::failed)

    private val surface = SurfaceView(context).apply {
        // Превью — картинка, а не элемент управления: TalkBack читает подсказку ниже.
        importantForAccessibility = View.IMPORTANT_FOR_ACCESSIBILITY_NO
        holder.addCallback(
            object : SurfaceHolder.Callback {
                override fun surfaceCreated(holder: SurfaceHolder) {
                    surfaceReady = true
                    openIfReady()
                }

                override fun surfaceChanged(holder: SurfaceHolder, format: Int, width: Int, height: Int) = Unit

                override fun surfaceDestroyed(holder: SurfaceHolder) {
                    surfaceReady = false
                    camera.close()
                }
            },
        )
    }
    private val frame = AspectFrame(context).apply {
        setBackgroundColor(context.getColor(R.color.surface_variant))
        addView(surface, FrameLayout.LayoutParams(FrameLayout.LayoutParams.WRAP_CONTENT, FrameLayout.LayoutParams.WRAP_CONTENT, Gravity.CENTER))
    }
    private val hint = Ui.text(context, R.style.Text_DPpass_Secondary, context.getString(R.string.qr_camera_hint))

    override fun content(): View = Ui.column(context, 12).apply {
        setPadding(Ui.dp(context, 16), Ui.dp(context, 8), Ui.dp(context, 16), Ui.dp(context, 24))
        addView(frame, LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, 0, 1f))
        addView(hint, Ui.matchWidth())
    }

    override fun render(status: TunnelStatus) {
        frame.ratio = ratio()
    }

    override fun onShown() {
        shown = true
        frame.ratio = ratio()
        // Вернулись после отказа камеры — новая попытка, прежнее сообщение ни к чему.
        hint.text = context.getString(R.string.qr_camera_hint)
        hint.setTextColor(context.getColor(R.color.text_secondary))
        openIfReady()
    }

    override fun onHidden() {
        shown = false
        camera.close()
    }

    private fun openIfReady() {
        if (shown && surfaceReady && !finished) camera.open(surface.holder)
    }

    private fun found(text: String) {
        if (finished) return
        finished = true
        surface.performHapticFeedback(HapticFeedbackConstants.CONTEXT_CLICK)
        camera.close()
        host.pop()
        host.importText(text)
    }

    private fun failed() {
        if (finished) return
        camera.close()
        hint.text = context.getString(R.string.qr_camera_failed)
        hint.setTextColor(context.getColor(R.color.error))
    }

    /** Ширина к высоте превью на экране: кадр камеры повёрнут относительно экрана ([QrCameraSizes.swapped]). */
    private fun ratio(): Float {
        val p = choice.preview
        val swapped = QrCameraSizes.swapped(choice.sensorDegrees, displayDegrees())
        return if (swapped) p.height.toFloat() / p.width else p.width.toFloat() / p.height
    }

    private fun displayDegrees(): Int {
        val rotation = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            context.display?.rotation ?: Surface.ROTATION_0
        } else {
            // До Android 11 поворот экрана — только так.
            @Suppress("DEPRECATION")
            context.windowManager.defaultDisplay.rotation
        }
        return when (rotation) {
            Surface.ROTATION_90 -> 90
            Surface.ROTATION_180 -> 180
            Surface.ROTATION_270 -> 270
            else -> 0
        }
    }

    /** Окно превью с пропорциями кадра: вписано в место и по центру, без растяжения. */
    // Создаётся только из кода экрана (D-34): конструктора для разметки XML не нужно.
    @SuppressLint("ViewConstructor")
    private class AspectFrame(context: Context) : FrameLayout(context) {
        var ratio: Float = 0f
            set(value) {
                if (field == value) return
                field = value
                requestLayout()
            }

        override fun onMeasure(widthMeasureSpec: Int, heightMeasureSpec: Int) {
            super.onMeasure(widthMeasureSpec, heightMeasureSpec)
            if (ratio <= 0f || childCount == 0) return
            var w = measuredWidth
            var h = (w / ratio).toInt()
            if (h > measuredHeight) {
                h = measuredHeight
                w = (h * ratio).toInt()
            }
            getChildAt(0).measure(MeasureSpec.makeMeasureSpec(w, MeasureSpec.EXACTLY), MeasureSpec.makeMeasureSpec(h, MeasureSpec.EXACTLY))
        }
    }
}
