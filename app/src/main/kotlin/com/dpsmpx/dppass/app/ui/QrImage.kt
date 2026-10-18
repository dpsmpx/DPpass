package com.dpsmpx.dppass.app.ui

import com.dpsmpx.dppass.diagnostics.DiagCode
import com.dpsmpx.dppass.diagnostics.Outcome
import com.google.zxing.BarcodeFormat
import com.google.zxing.BinaryBitmap
import com.google.zxing.DecodeHintType
import com.google.zxing.MultiFormatReader
import com.google.zxing.RGBLuminanceSource
import com.google.zxing.ReaderException
import com.google.zxing.common.HybridBinarizer

/**
 * QR с картинки (D-65): пиксели → текст, который дальше идёт тем же путём,
 * что буфер обмена (D-42): распознавание, сводка, подтверждение (T13).
 *
 * Распознаёт ZXing core и только формат QR. Картинка приходит уже
 * уменьшенной до [MAX_PIXELS] ([sampleSize]): память и время разбора
 * ограничены, какой бы ни была исходная. Текст в журнал не
 * пишется — в нём ссылки с секретами.
 */
internal object QrImage {
    /**
     * Пикселей после уменьшения — 2048²: снимок экрана телефона
     * (1080×2400) читается целиком, и мелкие модули плотного QR не
     * теряются; фото уменьшается. Память — до 16 МиБ на ARGB и столько же
     * на массив пикселей.
     */
    const val MAX_PIXELS: Long = 2048L * 2048

    /** Больше этого файл не читается: снимок экрана и фото с QR — единицы МиБ. */
    const val MAX_FILE_BYTES: Int = 32 * 1024 * 1024

    private val HINTS: Map<DecodeHintType, Any> = mapOf(
        DecodeHintType.POSSIBLE_FORMATS to listOf(BarcodeFormat.QR_CODE),
        DecodeHintType.TRY_HARDER to true,
        // Светлый код на тёмном фоне (тёмная тема в приложении поставщика).
        DecodeHintType.ALSO_INVERTED to true,
    )

    /**
     * Во сколько раз уменьшить картинку [width]×[height] при чтении
     * (степень двойки, как `BitmapFactory.Options.inSampleSize`), чтобы
     * пикселей осталось не больше [MAX_PIXELS]. Уменьшая, декодер
     * округляет размер вверх — запас на строку и столбец.
     */
    fun sampleSize(width: Int, height: Int): Int {
        require(width > 0 && height > 0)
        fun pixels(s: Int): Long = if (s == 1) width.toLong() * height else (width / s + 1).toLong() * (height / s + 1)
        var s = 1
        while (pixels(s) > MAX_PIXELS) s *= 2
        return s
    }

    /**
     * Первый QR-код на картинке [argb] (`width × height`, по строкам). Пустой
     * код — тоже «не найден»: импортировать нечего.
     */
    fun decode(argb: IntArray, width: Int, height: Int): Outcome<String> {
        require(width > 0 && height > 0 && argb.size == width * height)
        val bitmap = BinaryBitmap(HybridBinarizer(RGBLuminanceSource(width, height, argb)))
        val text = try {
            MultiFormatReader().decode(bitmap, HINTS).text
        } catch (e: ReaderException) {
            null
        }
        if (text.isNullOrBlank()) return Outcome.failure(DiagCode.IMPORT_QR_NOT_FOUND, NOT_FOUND)
        return Outcome.Success(text)
    }

    const val NOT_FOUND: String = "на картинке нет читаемого QR-кода: код целиком в кадре, резкий и не слишком мелкий"
}
