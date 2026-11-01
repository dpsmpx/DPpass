package com.dpsmpx.dppass.app

import android.os.Build
import com.dpsmpx.dppass.engine.ConnNetwork
import com.dpsmpx.dppass.engine.ConnState
import com.dpsmpx.dppass.engine.EngineConnection
import com.dpsmpx.dppass.engine.InboundKind
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.annotation.Config
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Приложение у соединения на JVM (D-106, D-108), на API 26, 29 и 36.
 *
 * - **Android 8–9 (API 26): у соединения из TUN — `null` (не узнать).**
 *   Телефон автора на Android 15, этот путь на нём не пройти (`TODO.md`);
 *   `getConnectionOwnerUid` есть только с API 29 (Q), до него DPpass
 *   даже не спрашивает — здесь это и видно.
 * - **API 29+: путь разрешения действует.** DPpass спрашивает UID по паре
 *   адресов из TUN; нет пакета у UID — запасной ярлык `uid N`. Так на JVM
 *   (`getConnectionOwnerUid` Robolectric даёт UID 0, пакета у него нет);
 *   настоящее имя пакета — на устройстве (Android 15, 31.10.2026, D-106).
 * - **Входы без TUN** (локальный прокси D-95, раздача D-51, свои запросы
 *   DPpass) — `null` на любом API: UID по паре адресов из TUN спрашивать
 *   не у чего.
 * - **Адрес не разобрать** — `null`: до обращения к системе.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [26, 29, 36])
class AppOwnersTest {
    private val belowQ = Build.VERSION.SDK_INT < Build.VERSION_CODES.Q
    private val owners = AppOwners(RuntimeEnvironment.getApplication())

    @Test
    fun tunConnectionOwnerDependsOnApiLevel() {
        val tun = tun("10.0.0.2:40000", "203.0.113.5:443", InboundKind.TUN)
        if (belowQ) {
            assertNull(owners.owner(tun), "Android 8–9 (API ${Build.VERSION.SDK_INT}): владелец не узнаётся")
        } else {
            val owner = owners.owner(tun)
            // Путь разрешения UID действует; без пакета у UID — запасной ярлык «uid N».
            assertTrue(owner != null && owner.startsWith("uid "), "API ${Build.VERSION.SDK_INT}: ожидался ярлык «uid N», а было «$owner»")
        }
    }

    @Test
    fun ownerIsUnknownForInboundsWithoutTun() {
        for (kind in listOf(InboundKind.LOCAL, InboundKind.SHARE, InboundKind.OTHER)) {
            assertNull(owners.owner(tun("10.0.0.2:40000", "203.0.113.5:443", kind)), "вход $kind: владелец должен быть не узнать")
        }
    }

    @Test
    fun ownerIsUnknownWhenAddressCannotBeParsed() {
        for (bad in listOf("", "no-port", "203.0.113.5:0", "203.0.113.5:70000", ":443", "not-an-ip:443")) {
            assertNull(owners.owner(tun(bad, "203.0.113.5:443", InboundKind.TUN)), "источник «$bad»: не узнать")
            assertNull(owners.owner(tun("10.0.0.2:40000", bad, InboundKind.TUN)), "назначение «$bad»: не узнать")
        }
    }

    private fun tun(source: String, target: String, inboundKind: InboundKind) = EngineConnection(
        id = 1,
        network = ConnNetwork.TCP,
        inbound = "tun-in",
        source = source,
        target = target,
        domain = "",
        protocol = "tls",
        route = "proxy",
        state = com.dpsmpx.dppass.engine.ConnState.OPEN,
        ageMillis = 0,
        durationMillis = 0,
        idleMillis = 0,
        firstByteMillis = -1,
        upBytes = 0,
        downBytes = 0,
        upChunks = 0,
        downChunks = 0,
        inboundKind = inboundKind,
    )
}
