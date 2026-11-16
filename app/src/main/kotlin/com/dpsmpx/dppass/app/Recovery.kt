package com.dpsmpx.dppass.app

/**
 * Расписание восстановления соединения (D-113): пропала сеть или выбранный
 * сервер не отвечает, а автопереключение выключено — DPpass держит тот же
 * сервер и пробует снова, с растущей паузой, пока пользователь не решит иначе.
 * Чистая логика — без Android, чтобы расписание проверялось тестом на JVM.
 */
internal object Recovery {
    /** Пауза после возвращения сети: Wi-Fi и мобильная сеть «мигают», переподключаться на первой секунде рано. */
    const val SETTLE_MILLIS = 3_000L

    /** Как часто смотреть, вернулась ли сеть, пока её нет. */
    const val NETWORK_POLL_MILLIS = 2_000L

    /** Как часто смотреть исход попытки подключения. */
    const val STATUS_POLL_MILLIS = 300L

    /** После стольких неудачных попыток при живой сети — уведомление с предложением сменить сервер. */
    const val NOTIFY_AFTER = 3

    private const val FIRST_MILLIS = 5_000L
    private const val MAX_MILLIS = 60_000L

    /** Пауза перед попыткой номер [failed] + 1: 5, 10, 20, 40 с, дальше — раз в минуту. */
    fun delayMillis(failed: Int): Long = (FIRST_MILLIS shl failed.coerceIn(0, 6)).coerceAtMost(MAX_MILLIS)
}
