package com.dpsmpx.dppass.app.ui

/**
 * Протяжка списка вниз (D-70): насколько опустился значок и хватит ли этого,
 * чтобы начать замер. Чистая логика без Android — проверяется на
 * компьютере; касания и отрисовка — в [PullToRefresh].
 *
 * Значок идёт за пальцем вдвое медленнее ([RESISTANCE]) и не дальше [maxPx]:
 * так видно, что список не прокручивается, а тянется. Замер — если при
 * отпускании значок дошёл до [thresholdPx]; вернул палец вверх — нет.
 */
class PullGesture(private val thresholdPx: Float, private val maxPx: Float) {
    init {
        require(thresholdPx > 0f && maxPx >= thresholdPx) { "порог $thresholdPx и предел $maxPx" }
    }

    /** Насколько опущен значок, пиксели. */
    var offset: Float = 0f
        private set

    /** Отпустить сейчас — начать замер. */
    val armed: Boolean get() = offset >= thresholdPx

    /** Доля пути до порога, 0…1: прозрачность и поворот значка. */
    val progress: Float get() = (offset / thresholdPx).coerceIn(0f, 1f)

    /** [pulledPx] — сколько палец прошёл вниз от начала протяжки; вверх — меньше нуля. */
    fun drag(pulledPx: Float) {
        offset = (pulledPx * RESISTANCE).coerceIn(0f, maxPx)
    }

    /** Палец отпущен: true — начать замер. Протяжка закончена в любом случае. */
    fun release(): Boolean = armed.also { offset = 0f }

    /** Касание отменено системой (например, жест «назад»): без замера. */
    fun cancel() {
        offset = 0f
    }

    companion object {
        const val RESISTANCE: Float = 0.5f
    }
}
