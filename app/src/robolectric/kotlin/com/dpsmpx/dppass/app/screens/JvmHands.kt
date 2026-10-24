package com.dpsmpx.dppass.app.screens

import android.app.Activity
import android.view.KeyEvent
import android.view.MotionEvent
import android.view.View
import com.dpsmpx.dppass.app.device.Device
import org.robolectric.shadows.ShadowDialog
import org.robolectric.shadows.ShadowLooper

/**
 * Руки тестов экранов на JVM (D-86). Тест под Robolectric идёт в главном
 * потоке приложения, а часы `SystemClock` там поддельные: ждать — настоящим
 * временем и прогоном главного потока (приложение работает и в фоне);
 * касание и «Назад» — прямо виду, а не через систему ввода, которой нет;
 * лист — показан ли последний диалог.
 */
class JvmHands : Device.Hands {
    override fun now(): Long = System.nanoTime() / NANOS_PER_MILLI

    override fun pause(millis: Long) {
        Thread.sleep(millis)
        ShadowLooper.idleMainLooper()
    }

    override fun pointer(view: View, event: MotionEvent) {
        view.rootView.dispatchTouchEvent(event)
    }

    /** «Назад» — окну сверху: листу, если он открыт. */
    override fun back() {
        val target = sheet()?.window?.decorView ?: return
        target.dispatchKeyEvent(KeyEvent(KeyEvent.ACTION_DOWN, KeyEvent.KEYCODE_BACK))
        target.dispatchKeyEvent(KeyEvent(KeyEvent.ACTION_UP, KeyEvent.KEYCODE_BACK))
    }

    override fun sheetShown(activity: Activity): Boolean = sheet() != null

    private fun sheet() = ShadowDialog.getLatestDialog()?.takeIf { it.isShowing }

    private companion object {
        const val NANOS_PER_MILLI = 1_000_000L
    }
}
