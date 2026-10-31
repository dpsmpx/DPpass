package com.dpsmpx.dppass.desktop

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** Раздача с ПК на Windows (D-101): что раздаёт — говорит ICS через мост; сомнение — не раздавать. */
class WindowsShareInterfacesTest {
    private fun reply(status: Int, text: String): ByteArray = byteArrayOf(status.toByte()) + text.toByteArray(Charsets.UTF_8)

    @Test
    fun privateSideOfIcsIsShared() {
        // «Мобильный хот-спот» — 192.168.137.1/24; второй адаптер ICS — тоже.
        val scan = WindowsShareInterfaces { reply(0, "192.168.138.1/24\n192.168.137.1/24\n192.168.137.1/24\n") }.find()
        assertEquals(listOf("192.168.137.1/24", "192.168.138.1/24"), scan.endpoints.map { it.toString() })
        assertEquals("", scan.absent)
        assertEquals("ics=0 shared=3 endpoints=2", scan.seen)
        assertTrue(listOf("192.168", "137").none { it in scan.seen }, "в журнал — без адресов (D-57)")
    }

    @Test
    fun noIcsMeansNoSharingWithHowToTurnItOn() {
        val scan = WindowsShareInterfaces { reply(0, "") }.find()
        assertTrue(scan.endpoints.isEmpty())
        assertTrue("Мобильный хот-спот" in scan.absent)
        assertEquals("ics=0 shared=0 endpoints=0", scan.seen)
    }

    @Test
    fun publicOrTooNarrowAddressIsNotAnEndpoint() {
        // Мост отдаёт адреса как есть; годен ли адрес для входа — решает ShareSpec (D-51).
        val scan = WindowsShareInterfaces { reply(0, "203.0.113.1/24\n10.42.0.1/31\n") }.find()
        assertTrue(scan.endpoints.isEmpty())
        assertTrue("Нет точки доступа" in scan.absent)
    }

    @Test
    fun anyDoubtMeansNoSharing() {
        val failed = WindowsShareInterfaces { reply(1, "менеджер общего доступа (ICS) не создан: HRESULT 0x80040154") }.find()
        assertTrue(failed.endpoints.isEmpty())
        assertEquals(WindowsShareInterfaces.FAILED, failed.absent)
        assertEquals("ics=failed kind=1 hr=0x80040154", failed.seen, "в журнал — вид отказа и код COM, не текст")
        assertEquals("ics=failed kind=-1", WindowsShareInterfaces { ByteArray(0) }.find().seen)
        // Одна неразобранная строка — весь ответ под сомнением.
        val unparsed = WindowsShareInterfaces { reply(0, "192.168.137.1/24\nне адрес\n") }.find()
        assertTrue(unparsed.endpoints.isEmpty())
        assertEquals(WindowsShareInterfaces.UNPARSED, unparsed.absent)
        assertEquals("ics=unparsed", unparsed.seen)
    }

    @Test
    fun linesAreParsedStrictly() {
        assertNull(WindowsShareInterfaces.parse(listOf("192.168.137.1")), "без длины префикса")
        assertNull(WindowsShareInterfaces.parse(listOf("fe80::1/64")), "IPv6 мост не отдаёт; пришёл — ответ не тот")
        assertNull(WindowsShareInterfaces.parse(listOf("192.168.137.1/33")))
        assertNull(WindowsShareInterfaces.parse(listOf("192.168.137.1/x")))
        assertEquals(24, WindowsShareInterfaces.parse(listOf("192.168.137.1/24"))!!.single().second)
    }

    @Test
    fun windowTextsSpeakOfWindowsNotNetworkManager() {
        val shares = WindowsShareInterfaces { reply(0, "") }
        assertTrue("Мобильный хот-спот" in shares.condition)
        assertTrue("Брандмауэр" in shares.firewall)
        assertTrue(listOf(shares.condition, shares.firewall, WindowsShareInterfaces.NO_HOTSPOT).none { "NetworkManager" in it })
    }
}
