package com.dpsmpx.dppass.desktop

/**
 * Функции оболочки Linux в мосте ядра (`tools/xray/jni/desktop.go`, D-74):
 * то, что на Android даёт `VpnService`. Библиотека та же, что у ядра
 * (`libdppassxray.so`), её загружает [DesktopGraph]. Ответ — fd или 0 при
 * успехе, иначе −errno. Вызывается только из этого модуля.
 */
internal object LinuxNative {
    /** Открыть TUN [name] (`IFF_TUN | IFF_NO_PI`, не постоянный): fd или −errno. */
    @JvmStatic external fun nativeOpenTun(name: ByteArray): Int

    @JvmStatic external fun nativeCloseFd(fd: Int): Int

    /** Метка `SO_MARK` на сокете: 0 или −errno. */
    @JvmStatic external fun nativeMarkSocket(fd: Int, mark: Int): Int

    /** Резолвер Go процесса — с меткой на своих сокетах (имена серверов мимо туннеля, D-29). */
    @JvmStatic external fun nativeMarkResolver(mark: Int): Int
}
