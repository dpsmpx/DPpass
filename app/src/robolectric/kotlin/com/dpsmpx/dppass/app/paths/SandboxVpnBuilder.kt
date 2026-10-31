package com.dpsmpx.dppass.app.paths

import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import org.robolectric.annotation.Implementation
import org.robolectric.annotation.Implements
import org.robolectric.annotation.RealObject
import java.net.Inet4Address
import java.net.InetAddress

/**
 * `VpnService.Builder` в песочнице (D-90). У Robolectric нет службы пакетов
 * для проверки приложений из политики — проверка пропускается; на JVM нет
 * TUN — `establish()` отвечает, как велит тест ([answer]): `null`, как
 * Android без согласия, или исключение, как Android, отвергший параметры.
 */
@Implements(VpnService.Builder::class)
class SandboxVpnBuilder {
    @RealObject
    private lateinit var real: VpnService.Builder

    @Implementation
    fun verifyApp(packageName: String) = Unit

    @Implementation
    fun establish(): ParcelFileDescriptor? = answer()

    /**
     * Android 8–10 на JVM (D-108): настоящий `addRoute` строит `RouteInfo`,
     * а тот читает поле `Inet4Address.ANY`, которое есть только в libcore
     * Android, — `NoSuchFieldError` (31.10.2026). Здесь — те же проверки,
     * что у Builder: не петля, префикс — в пределах семейства, бит адреса
     * за префиксом нет. С Android 11 работает настоящий метод.
     */
    @Implementation(maxSdk = Build.VERSION_CODES.Q)
    fun addRoute(address: InetAddress, prefixLength: Int): VpnService.Builder {
        val bytes = address.address
        require(!address.isLoopbackAddress) { "Bad address" }
        require(prefixLength in 0..(if (address is Inet4Address) 32 else 128)) { "Bad prefixLength" }
        for (i in bytes.indices) {
            val keep = (prefixLength - i * 8).coerceIn(0, 8)
            val mask = (0xff shl (8 - keep)) and 0xff
            require(bytes[i].toInt() and mask.inv() and 0xff == 0) { "Bad address" }
        }
        return real
    }

    companion object {
        @JvmStatic
        var answer: () -> ParcelFileDescriptor? = { null }
    }
}
