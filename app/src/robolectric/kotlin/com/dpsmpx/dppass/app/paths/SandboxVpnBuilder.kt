package com.dpsmpx.dppass.app.paths

import android.net.VpnService
import android.os.ParcelFileDescriptor
import org.robolectric.annotation.Implementation
import org.robolectric.annotation.Implements

/**
 * `VpnService.Builder` в песочнице (D-90). У Robolectric нет службы пакетов
 * для проверки приложений из политики — проверка пропускается; на JVM нет
 * TUN — `establish()` отвечает, как велит тест ([answer]): `null`, как
 * Android без согласия, или исключение, как Android, отвергший параметры.
 */
@Implements(VpnService.Builder::class)
class SandboxVpnBuilder {
    @Implementation
    fun verifyApp(packageName: String) = Unit

    @Implementation
    fun establish(): ParcelFileDescriptor? = answer()

    companion object {
        @JvmStatic
        var answer: () -> ParcelFileDescriptor? = { null }
    }
}
