package com.dpsmpx.dppass.connection

import com.dpsmpx.dppass.core.IpAddress
import com.dpsmpx.dppass.core.ManualClock
import com.dpsmpx.dppass.diagnostics.DiagCode
import com.dpsmpx.dppass.diagnostics.Outcome
import com.dpsmpx.dppass.engine.ShareSpec
import com.dpsmpx.dppass.storage.InMemoryBlobStore
import com.dpsmpx.dppass.storage.Quarantine
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** Раздача туннеля другим устройствам (D-51): настройки, хранение, вход для ядра. */
class ShareSettingsTest {
    private val clock = ManualClock(1_000)

    @Test
    fun generatedSettingsAreOffRandomAndInRange() {
        val a = ShareSettings.generate()
        val b = ShareSettings.generate()
        assertFalse(a.enabled, "раздача выключена по умолчанию")
        assertTrue(a.port in ShareSettings.PORT_FROM until ShareSettings.PORT_UNTIL)
        assertEquals(ShareSettings.USER_LENGTH, a.user.reveal().length)
        assertEquals(ShareSettings.PASSWORD_LENGTH, a.password.reveal().length)
        assertNotEquals(a.password.reveal(), b.password.reveal(), "пароль случайный")
    }

    @Test
    fun specOnlyWhenEnabledAndOnPrivateAddresses() {
        val s = ShareSettings.generate().copy(enabled = true, port = 41234)
        val hotspot = ShareSpec.Endpoint(IpAddress.parse("192.168.43.1")!!, 24)
        val spec = s.spec(listOf(hotspot, hotspot))!!
        assertEquals(listOf(hotspot), spec.endpoints, "повтор адреса отброшен")
        assertEquals(41234, spec.port)
        assertNull(s.copy(enabled = false).spec(listOf(hotspot)), "выключено — без входа")
        assertNull(s.spec(emptyList()), "нет интерфейсов раздачи — без входа")
    }

    @Test
    fun storeRoundTripKeepsCredentialsAndNoPlainSecretsLeak() {
        val blobs = InMemoryBlobStore()
        val service = ShareService(ShareStore(blobs, Quarantine(blobs, clock)))
        val first = service.current().valueOrNull()!!
        assertFalse(first.enabled)
        val on = service.setEnabled(true).valueOrNull()!!
        assertTrue(on.enabled)
        assertEquals(first.password.reveal(), on.password.reveal(), "включение не меняет пароль")
        val again = ShareService(ShareStore(blobs, Quarantine(blobs, clock))).current().valueOrNull()!!
        assertEquals(on.port, again.port)
        assertEquals(on.user.reveal(), again.user.reveal())
        assertEquals(on.password.reveal(), again.password.reveal())
        assertTrue(again.enabled, "переживает перезапуск")
        val renewed = service.regenerate().valueOrNull()!!
        assertTrue(renewed.enabled, "смена пароля не выключает раздачу")
        assertNotEquals(on.password.reveal(), renewed.password.reveal())
        // Строковое представление — без секретов.
        assertFalse(renewed.password.reveal() in renewed.toString())
    }

    // D-56: у сопряжённого устройства — свой вход; отзыв убирает только его, смена пароля — всех.
    @Test
    fun pairedDevicesHaveOwnLoginAndCanBeRevoked() {
        val blobs = InMemoryBlobStore()
        val service = ShareService(ShareStore(blobs, Quarantine(blobs, clock)))
        val main = service.setEnabled(true).valueOrNull()!!
        val a = service.pair("realme", 5_000).valueOrNull()!!
        val b = service.pair("Планшет", 6_000).valueOrNull()!!
        assertEquals(setOf(main.user.reveal(), a.user.reveal(), b.user.reveal()).size, 3, "логины не повторяются")
        assertNotEquals(a.password.reveal(), b.password.reveal())
        val hotspot = ShareSpec.Endpoint(IpAddress.parse("192.168.43.1")!!, 24)
        val spec = service.current().valueOrNull()!!.spec(listOf(hotspot))!!
        assertEquals(listOf(main.user, a.user, b.user), spec.accounts.map { it.user })

        val again = ShareService(ShareStore(blobs, Quarantine(blobs, clock))).current().valueOrNull()!!
        assertEquals(listOf("realme", "Планшет"), again.paired.map { it.name }, "переживает перезапуск")
        assertEquals(a.password.reveal(), again.paired.first().password.reveal())

        val revoked = service.unpair(a.id).valueOrNull()!!
        assertEquals(listOf(b.id), revoked.paired.map { it.id })
        assertEquals(main.password.reveal(), revoked.password.reveal(), "отзыв одного не трогает основной вход")
        assertTrue(service.regenerate().valueOrNull()!!.paired.isEmpty(), "новые логин и пароль — сопряжённых больше нет")

        repeat(ShareSettings.MAX_PAIRED) { assertTrue(service.pair("d$it", 0) is Outcome.Success) }
        assertEquals(DiagCode.LIMIT_EXCEEDED, service.pair("лишнее", 0).errors.single().code)
        assertEquals(DiagCode.NAME_INVALID, ShareService(ShareStore(InMemoryBlobStore(), Quarantine(blobs, clock))).pair(" ", 0).errors.single().code)
    }

    @Test
    fun oldShareFormatsRequirePairingAndNewKeysSurviveRoundTrip() {
        for (version in listOf(1, 2)) {
            val old = """{"format":"dppass.share","format_version":$version,"enabled":true,"port":41234,"user":"u-test","password":"p-test"}"""
            assertEquals(DiagCode.FORMAT_VERSION_UNSUPPORTED, ShareCodec.read(old).errors.single().code)
        }
        val fresh = ShareSettings.generate()
        assertEquals(fresh, ShareCodec.read(ShareCodec.write(fresh)).valueOrNull())
        assertTrue("\"format_version\":3" in ShareCodec.write(fresh))
    }

    @Test
    fun corruptedSettingsGoToQuarantineAndShareIsOff() {
        val blobs = InMemoryBlobStore()
        blobs.write(ShareStore.KEY, """{"format":"dppass.share","format_version":1,"enabled":true,"port":80,"user":"u","password":"p"}""".toByteArray())
        val r = ShareStore(blobs, Quarantine(blobs, clock)).load()
        assertFalse(r.valueOrNull()!!.enabled, "нечитаемое — раздача выключена, а не включена с чужим паролем")
        assertTrue(r.diagnostics.any { it.code == DiagCode.STORAGE_CORRUPTED })
        assertEquals(1, Quarantine(blobs, clock).list().valueOrNull()!!.size)
    }
}
