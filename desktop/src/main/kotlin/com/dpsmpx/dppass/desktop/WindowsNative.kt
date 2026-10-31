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

    /** Тема приложений пользователя (`AppsUseLightTheme`): 1 — светлая, 0 — тёмная, -1 — не узнать. */
    @JvmStatic external fun nativeSystemTheme(): Int

    /**
     * Интерфейс проб мимо туннеля (D-99): после статуса — номер интерфейса
     * маршрута по умолчанию мимо адаптера [tunAlias] и его серверы DNS по
     * строке ([WindowsProbeNetwork.parseInterface]).
     */
    @JvmStatic external fun nativeProbeInterface(tunAlias: ByteArray): ByteArray

    /** Привязать сокет [handle] (SOCKET канала JDK) к интерфейсу [index] — IP_UNICAST_IF (D-99); ответ — статус. */
    @JvmStatic external fun nativeBindSocket(handle: Long, index: Int): ByteArray

    /** Адреса имени [host] у серверов [servers] (адреса по строке) сокетами с привязкой к [index] (D-99). */
    @JvmStatic external fun nativeResolveVia(host: ByteArray, servers: ByteArray, index: Int, timeoutMillis: Int): ByteArray
}
