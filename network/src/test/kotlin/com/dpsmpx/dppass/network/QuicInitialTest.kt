package com.dpsmpx.dppass.network

import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/** Пакет QUICv1 Initial пробы UDP (D-60): ключи и маска по RFC 9001, приложение A; устройство пакета; ответ сервера. */
class QuicInitialTest {
    private val hex = QuicInitial::hex

    @Test
    fun keysAndHeaderMaskMatchRfc9001Vectors() {
        // RFC 9001, A.1: идентификатор назначения клиента 0x8394c8f03e515708.
        val dcid = hex("8394c8f03e515708")
        assertContentEquals(hex("c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea"), QuicInitial.clientSecret(dcid))
        val keys = QuicInitial.clientKeys(dcid)
        assertContentEquals(hex("1f369613dd76d5467730efcbe3b1a22d"), keys.key)
        assertContentEquals(hex("fa044b2f42a3fd3b46fb255c"), keys.iv)
        assertContentEquals(hex("9f50449e04a0e810283a1e9933adedd2"), keys.hp)
        // RFC 9001, A.2: образец шифртекста и первые 5 байт маски.
        assertContentEquals(hex("437b9aec36"), QuicInitial.mask(keys.hp, hex("d1b1c98dd7689fb8ec11d242b123dc9b")).copyOf(5))
    }

    @Test
    fun packetIsAFullSizeV1InitialWithTheLandmarkName() {
        val p = QuicInitial.build("probe.example.org", SecureRandom())
        val b = p.bytes
        assertTrue(b.size >= QuicInitial.MIN_DATAGRAM, "датаграмма ${b.size} байт")
        assertEquals(0xC0, b[0].toInt() and 0xF0, "длинный заголовок, тип Initial")
        assertContentEquals(byteArrayOf(0, 0, 0, 1), b.copyOfRange(1, 5), "версия 1")
        assertEquals(8, b[5].toInt())
        assertContentEquals(p.destinationId, b.copyOfRange(6, 14))
        assertEquals(8, b[14].toInt())
        assertContentEquals(p.sourceId, b.copyOfRange(15, 23))

        // Снять защиту так, как это делает сервер (и фильтр): маска, номер пакета, AEAD.
        val keys = QuicInitial.clientKeys(p.destinationId)
        val pnOffset = 23 + 1 + 2 // пустой токен, длина — 2 байта
        val m = QuicInitial.mask(keys.hp, b.copyOfRange(pnOffset + 4, pnOffset + 20))
        val first = b[0].toInt() xor (m[0].toInt() and 0x0f)
        assertEquals(3, first and 0x03, "номер пакета — 4 байта")
        val header = b.copyOfRange(0, pnOffset + 4).also {
            it[0] = first.toByte()
            for (i in 0 until 4) it[pnOffset + i] = (it[pnOffset + i].toInt() xor m[1 + i].toInt()).toByte()
        }
        assertContentEquals(byteArrayOf(0, 0, 0, 0), header.copyOfRange(pnOffset, pnOffset + 4))
        val length = ((b[pnOffset - 2].toInt() and 0x3f) shl 8) or (b[pnOffset - 1].toInt() and 0xff)
        assertEquals(b.size - pnOffset, length, "поле длины — до конца датаграммы")
        val plain = Cipher.getInstance("AES/GCM/NoPadding").run {
            init(Cipher.DECRYPT_MODE, SecretKeySpec(keys.key, "AES"), GCMParameterSpec(128, keys.iv))
            updateAAD(header)
            doFinal(b, pnOffset + 4, b.size - pnOffset - 4)
        }
        assertEquals(0x06, plain[0].toInt(), "кадр CRYPTO")
        assertEquals(0x01, plain[4].toInt(), "в нём — ClientHello")
        val text = String(plain, Charsets.ISO_8859_1)
        assertTrue("probe.example.org" in text, "SNI ориентира")
        assertTrue("h3" in text, "ALPN")
        assertTrue(String(p.sourceId, Charsets.ISO_8859_1) in text, "initial_source_connection_id")
    }

    @Test
    fun onlyAReplyToOurConnectionCounts() {
        val scid = hex("0102030405060708")
        fun reply(version: Int, id: ByteArray, form: Int = 0xC0) =
            byteArrayOf(form.toByte(), (version ushr 24).toByte(), (version ushr 16).toByte(), (version ushr 8).toByte(), version.toByte(), id.size.toByte()) + id + ByteArray(20)
        val initial = reply(1, scid)
        assertTrue(QuicInitial.isResponse(initial, initial.size, scid), "Initial сервера")
        val negotiation = reply(0, scid, form = 0x80)
        assertTrue(QuicInitial.isResponse(negotiation, negotiation.size, scid), "согласование версии")
        val other = reply(1, hex("0807060504030201"))
        assertFalse(QuicInitial.isResponse(other, other.size, scid), "чужое соединение")
        val v2 = reply(0x6b3343cf, scid)
        assertFalse(QuicInitial.isResponse(v2, v2.size, scid), "другая версия")
        val short = reply(1, scid, form = 0x40)
        assertFalse(QuicInitial.isResponse(short, short.size, scid), "короткий заголовок")
        assertFalse(QuicInitial.isResponse(initial, 5, scid), "обрезанный")
    }
}
