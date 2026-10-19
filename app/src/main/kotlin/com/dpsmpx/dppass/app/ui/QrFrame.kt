package com.dpsmpx.dppass.app.ui

import com.google.zxing.BarcodeFormat
import com.google.zxing.BinaryBitmap
import com.google.zxing.DecodeHintType
import com.google.zxing.MultiFormatReader
import com.google.zxing.PlanarYUVLuminanceSource
import com.google.zxing.ReaderException
import com.google.zxing.common.HybridBinarizer

/**
 * Кадр камеры → QR (D-71): яркость кадра (плоскость Y у `YUV_420_888`) —
 * прямо в ZXing core, без копии в цвет. Тот же распознаватель, что у QR с
 * картинки (D-65), но кадров много: разбор быстрый, без `TRY_HARDER`; не
 * нашёл в этом кадре — найдёт в следующем. Чистая логика без Android —
 * проверяется на компьютере.
 */
internal object QrFrame {
    private val HINTS: Map<DecodeHintType, Any> = mapOf(
        DecodeHintType.POSSIBLE_FORMATS to listOf(BarcodeFormat.QR_CODE),
        // Светлый код на тёмном фоне (тёмная тема в приложении поставщика).
        DecodeHintType.ALSO_INVERTED to true,
    )

    /**
     * Текст первого QR-кода в кадре; null — в этом кадре его нет (или он
     * пустой). [luma] — яркость по строкам с шагом [rowStride]: у камеры
     * строка в памяти бывает длиннее кадра, и последняя строка — без
     * хвоста. [read] — распознаватель (в тестах — свой).
     */
    fun decode(
        luma: ByteArray,
        width: Int,
        height: Int,
        rowStride: Int = width,
        read: (BinaryBitmap) -> String = { MultiFormatReader().decode(it, HINTS).text },
    ): String? {
        require(width > 0 && height > 0 && rowStride >= width && luma.size >= rowStride.toLong() * (height - 1) + width)
        val source = PlanarYUVLuminanceSource(luma, rowStride, height, 0, 0, width, height, false)
        return try {
            read(BinaryBitmap(HybridBinarizer(source))).takeIf { it.isNotBlank() }
        } catch (e: ReaderException) {
            null
        } catch (e: RuntimeException) {
            // Кадр — чужие данные: на смазанном ZXing бывает и не ReaderException.
            // Для камеры это «в этом кадре нет», следующий кадр — через миг.
            null
        }
    }
}

/** Размер кадра в пикселях — без `android.util.Size`, чтобы проверять на компьютере. */
internal data class FrameSize(val width: Int, val height: Int) {
    val area: Long get() = width.toLong() * height

    /** Тот же формат кадра (16:9, 4:3…) с точностью до процента. */
    fun sameShape(other: FrameSize): Boolean = kotlin.math.abs(width.toLong() * other.height - other.width.toLong() * height) * 100 <= area
}

/** Какие размеры просить у камеры и как повёрнут её кадр относительно экрана (D-71). */
internal object QrCameraSizes {
    /**
     * Кадры для распознавания — не больше 1280×720: QR на экране телефона
     * читается и так, а разбор больших кадров медленнее. Превью — того же
     * формата, не больше 1920×1080: такое сочетание камера обязана
     * поддерживать на любом уровне Camera2 (размер PREVIEW).
     */
    val MAX_FRAME = FrameSize(1280, 720)
    val MAX_PREVIEW = FrameSize(1920, 1080)

    /**
     * Пара (кадр для распознавания, превью) из того, что камера умеет;
     * null — камера не отдаёт ни одного размера. Если подходящего по
     * пределу нет — самый маленький: лучше медленно, чем никак.
     */
    fun choose(frames: List<FrameSize>, previews: List<FrameSize>): Pair<FrameSize, FrameSize>? {
        val frame = pick(frames, MAX_FRAME) ?: return null
        val preview = pick(previews.filter { it.sameShape(frame) }, MAX_PREVIEW) ?: pick(previews, MAX_PREVIEW) ?: return null
        return frame to preview
    }

    private fun pick(sizes: List<FrameSize>, max: FrameSize): FrameSize? =
        sizes.filter { fits(it, max) }.maxByOrNull { it.area } ?: sizes.minByOrNull { it.area }

    // Предел — по длинной и короткой стороне: 720×1280 тоже влезает в 1280×720.
    private fun fits(s: FrameSize, max: FrameSize): Boolean =
        maxOf(s.width, s.height) <= maxOf(max.width, max.height) && minOf(s.width, s.height) <= minOf(max.width, max.height)

    /**
     * Кадр камеры на экране — с переставленными шириной и высотой: матрица
     * камеры повёрнута относительно экрана на четверть оборота. [sensorDegrees]
     * — `SENSOR_ORIENTATION`, [displayDegrees] — поворот экрана (0, 90, 180,
     * 270). Превью в `SurfaceView` камера поворачивает сама, а пропорции
     * окна под него — наша забота.
     */
    fun swapped(sensorDegrees: Int, displayDegrees: Int): Boolean = ((sensorDegrees - displayDegrees) % 180 + 180) % 180 != 0
}
