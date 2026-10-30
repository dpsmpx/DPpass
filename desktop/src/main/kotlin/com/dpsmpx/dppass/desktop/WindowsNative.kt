package com.dpsmpx.dppass.desktop

/**
 * Функции оболочки Windows в мосте ядра (`tools/xray/jni/windows.go`,
 * D-97). Библиотека та же, что у ядра (`dppassxray.dll`, комплект
 * Windows); в библиотеке для Linux их нет. Ответ байтами — статус первым
 * байтом (0 — успех, иначе вид отказа моста), затем данные или текст
 * ошибки. Вызывается только из этого модуля.
 */
internal object WindowsNative {
    /** Данные под DPAPI текущего пользователя Windows (ключ данных хранилища). */
    @JvmStatic external fun nativeProtect(plain: ByteArray): ByteArray

    /** Обратное [nativeProtect]; чужой или испорченный блок — отказ. */
    @JvmStatic external fun nativeUnprotect(sealed: ByteArray): ByteArray

    /** Процесс запущен с правами администратора: без них ядро не создаст адаптер Wintun. */
    @JvmStatic external fun nativeElevated(): Boolean

    /**
     * Маршрут по умолчанию мимо адаптера [tunAlias] (UTF-8): после статуса —
     * «0» или «1» (адаптер поднят), затем, если маршрут есть, строка
     * «псевдоним, шлюз, вид» через табуляцию ([WindowsHost.parseRoute]).
     */
    @JvmStatic external fun nativeDefaultRoute(tunAlias: ByteArray): ByteArray
}
