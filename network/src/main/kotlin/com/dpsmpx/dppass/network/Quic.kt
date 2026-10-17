package com.dpsmpx.dppass.network

import java.io.ByteArrayOutputStream
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * Пакет QUICv1 Initial для пробы UDP (D-60): ClientHello TLS 1.3 с SNI
 * ориентира в защищённом пакете Initial (RFC 9000, §17.2.2; RFC 9001,
 * §5). Фильтр расшифровывает именно QUICv1 Initial и решает по SNI
 * (`docs/research/RUSSIA_NETWORK_RESTRICTIONS.md`, L2, A: FOCI 2026),
 * поэтому проба — такой же пакет, как у настоящего клиента QUIC, а не
 * пакет другой версии, который фильтр пропустил бы.
 *
 * Рукопожатие не доводится: ключ обмена — случайные 32 байта без
 * закрытого ключа, сеанса не будет. Любой ответ сервера на этот пакет
 * ([isResponse]) значит «пакет прошёл».
 */
object QuicInitial {
    const val VERSION_1: Int = 1

    /** Наименьшая датаграмма с Initial клиента (RFC 9000, §14.1). */
    const val MIN_DATAGRAM: Int = 1200

    private const val ID_BYTES = 8
    private const val PN_BYTES = 4
    private const val TAG_BYTES = 16
    private val SALT_V1 = hex("38762cf7f55934b34d179ae6a4c80cadccbb7f0a")

    /** Датаграмма и идентификаторы соединения: ответ сервера адресован [sourceId]. */
    class Packet(val bytes: ByteArray, val destinationId: ByteArray, val sourceId: ByteArray)

    internal class Keys(val key: ByteArray, val iv: ByteArray, val hp: ByteArray)

    fun build(serverName: String, random: SecureRandom): Packet {
        val dcid = ByteArray(ID_BYTES).also(random::nextBytes)
        val scid = ByteArray(ID_BYTES).also(random::nextBytes)
        val hello = clientHello(serverName, scid, ByteArray(32).also(random::nextBytes), ByteArray(32).also(random::nextBytes))
        return Packet(protect(dcid, scid, crypto(hello)), dcid, scid)
    }

    /**
     * Ответ сервера на наш Initial: длинный заголовок, версия 1 или
     * согласование версии (0), а назначение — наш [sourceId]. Чужой или
     * случайный пакет его не угадает: идентификатор — 8 случайных байт.
     */
    fun isResponse(data: ByteArray, length: Int, sourceId: ByteArray): Boolean {
        if (length < 6 || data[0].toInt() and 0x80 == 0) return false
        val version = ((data[1].toInt() and 0xff) shl 24) or ((data[2].toInt() and 0xff) shl 16) or
            ((data[3].toInt() and 0xff) shl 8) or (data[4].toInt() and 0xff)
        if (version != VERSION_1 && version != 0) return false
        val idLength = data[5].toInt() and 0xff
        if (idLength != sourceId.size || length < 6 + idLength) return false
        return (0 until idLength).all { data[6 + it] == sourceId[it] }
    }

    /** Секрет клиента для Initial (RFC 9001, §5.2): по идентификатору назначения. */
    internal fun clientSecret(dcid: ByteArray): ByteArray = expandLabel(hmac(SALT_V1, dcid), "client in", 32)

    internal fun clientKeys(dcid: ByteArray): Keys {
        val secret = clientSecret(dcid)
        return Keys(expandLabel(secret, "quic key", 16), expandLabel(secret, "quic iv", 12), expandLabel(secret, "quic hp", 16))
    }

    /** Маска защиты заголовка (RFC 9001, §5.4.3): один блок AES-128 от 16 байт образца шифртекста. */
    internal fun mask(hp: ByteArray, sample: ByteArray): ByteArray =
        Cipher.getInstance("AES/ECB/NoPadding").apply { init(Cipher.ENCRYPT_MODE, SecretKeySpec(hp, "AES")) }.doFinal(sample, 0, 16)

    /** Пакет Initial (RFC 9000, §17.2.2) с номером 0 и заполнением до [MIN_DATAGRAM]. */
    private fun protect(dcid: ByteArray, scid: ByteArray, frames: ByteArray): ByteArray {
        val keys = clientKeys(dcid)
        // Первый байт, версия, два идентификатора с длинами, пустой токен, длина (2 байта), номер пакета.
        val headerBytes = 1 + 4 + 1 + dcid.size + 1 + scid.size + 1 + 2 + PN_BYTES
        val payload = frames.copyOf(maxOf(frames.size, MIN_DATAGRAM - headerBytes - TAG_BYTES)) // нули — кадры PADDING
        val header = Bytes().apply {
            u8(0xC0 or (PN_BYTES - 1)) // длинный заголовок, тип Initial
            u32(VERSION_1)
            u8(dcid.size)
            raw(dcid)
            u8(scid.size)
            raw(scid)
            varint(0) // длина токена
            varint2(PN_BYTES + payload.size + TAG_BYTES)
            u32(0) // номер пакета
        }.bytes()
        check(header.size == headerBytes)
        // Номер пакета 0: одноразовое число — сам iv (RFC 9001, §5.3).
        val sealed = Cipher.getInstance("AES/GCM/NoPadding").run {
            init(Cipher.ENCRYPT_MODE, SecretKeySpec(keys.key, "AES"), GCMParameterSpec(TAG_BYTES * 8, keys.iv))
            updateAAD(header)
            doFinal(payload)
        }
        val packet = header + sealed
        val pnOffset = header.size - PN_BYTES
        val m = mask(keys.hp, packet.copyOfRange(pnOffset + 4, pnOffset + 20))
        packet[0] = (packet[0].toInt() xor (m[0].toInt() and 0x0f)).toByte()
        for (i in 0 until PN_BYTES) packet[pnOffset + i] = (packet[pnOffset + i].toInt() xor m[1 + i].toInt()).toByte()
        return packet
    }

    /** Кадр CRYPTO (RFC 9000, §19.6) со смещением 0. */
    private fun crypto(data: ByteArray): ByteArray = Bytes().apply {
        u8(0x06)
        varint(0)
        varint2(data.size)
        raw(data)
    }.bytes()

    /**
     * ClientHello TLS 1.3 (RFC 8446, §4.1.2) для QUIC (RFC 9001, §8): SNI,
     * ALPN `h3`, только TLS 1.3, X25519, параметры транспорта с
     * идентификатором источника; пустой `legacy_session_id`.
     */
    internal fun clientHello(serverName: String, scid: ByteArray, helloRandom: ByteArray, keyShare: ByteArray): ByteArray {
        val name = serverName.toByteArray(Charsets.US_ASCII)
        val body = Bytes().apply {
            u16(0x0303)
            raw(helloRandom)
            u8(0) // legacy_session_id
            vec16 { listOf(0x1301, 0x1302, 0x1303).forEach(::u16) }
            vec8 { u8(0) } // сжатие — нет
            vec16 {
                extension(0x0000) {
                    vec16 {
                        u8(0) // host_name
                        vec16 { raw(name) }
                    }
                }
                extension(0x000a) { vec16 { u16(0x001d) } }
                extension(0x000d) { vec16 { listOf(0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601).forEach(::u16) } }
                extension(0x0010) { vec16 { vec8 { raw("h3".toByteArray(Charsets.US_ASCII)) } } }
                extension(0x002b) { vec8 { u16(0x0304) } }
                extension(0x0033) {
                    vec16 {
                        u16(0x001d)
                        vec16 { raw(keyShare) }
                    }
                }
                extension(0x0039) {
                    parameter(0x0f) { raw(scid) } // initial_source_connection_id
                    parameter(0x01) { varint(30_000) } // max_idle_timeout
                    parameter(0x04) { varint(1_048_576) } // initial_max_data
                }
            }
        }.bytes()
        return Bytes().apply {
            u8(0x01) // client_hello
            u24(body.size)
            raw(body)
        }.bytes()
    }

    private fun Bytes.extension(type: Int, content: Bytes.() -> Unit) {
        u16(type)
        vec16(content)
    }

    /** Параметр транспорта QUIC (RFC 9000, §18): номер, длина и значение — переменной длины. */
    private fun Bytes.parameter(id: Int, content: Bytes.() -> Unit) {
        val value = Bytes().apply(content).bytes()
        varint(id)
        varint(value.size)
        raw(value)
    }

    private fun hmac(key: ByteArray, data: ByteArray): ByteArray =
        Mac.getInstance("HmacSHA256").run {
            init(SecretKeySpec(key, "HmacSHA256"))
            doFinal(data)
        }

    /** HKDF-Expand-Label TLS 1.3 (RFC 8446, §7.1) с пустым контекстом. */
    private fun expandLabel(secret: ByteArray, label: String, length: Int): ByteArray {
        val full = ("tls13 $label").toByteArray(Charsets.US_ASCII)
        val info = Bytes().apply {
            u16(length)
            u8(full.size)
            raw(full)
            u8(0)
        }.bytes()
        // HKDF-Expand (RFC 5869): блоки T(i) = HMAC(PRK, T(i-1) | info | i).
        val out = ByteArrayOutputStream()
        var previous = ByteArray(0)
        var i = 1
        while (out.size() < length) {
            previous = hmac(secret, previous + info + byteArrayOf(i.toByte()))
            out.write(previous)
            i++
        }
        return out.toByteArray().copyOf(length)
    }

    internal fun hex(s: String): ByteArray = ByteArray(s.length / 2) { s.substring(it * 2, it * 2 + 2).toInt(16).toByte() }

    /** Запись полей TLS и QUIC в сетевом порядке байт. */
    private class Bytes {
        private val out = ByteArrayOutputStream()

        fun u8(v: Int) = out.write(v and 0xff)

        fun u16(v: Int) {
            u8(v ushr 8)
            u8(v)
        }

        fun u24(v: Int) {
            u8(v ushr 16)
            u16(v)
        }

        fun u32(v: Int) {
            u16(v ushr 16)
            u16(v)
        }

        fun raw(b: ByteArray) = out.write(b)

        /** Целое переменной длины (RFC 9000, §16): 1, 2 или 4 байта. */
        fun varint(v: Int) {
            require(v in 0 until (1 shl 30))
            when {
                v < 64 -> u8(v)
                v < 16_384 -> u16(0x4000 or v)
                else -> u32(0x8000_0000.toInt() or v)
            }
        }

        /** Всегда 2 байта: длину пакета пишем до шифрования. */
        fun varint2(v: Int) {
            require(v in 0 until 16_384)
            u16(0x4000 or v)
        }

        fun vec8(content: Bytes.() -> Unit) {
            val b = Bytes().apply(content).bytes()
            u8(b.size)
            raw(b)
        }

        fun vec16(content: Bytes.() -> Unit) {
            val b = Bytes().apply(content).bytes()
            u16(b.size)
            raw(b)
        }

        fun bytes(): ByteArray = out.toByteArray()
    }
}
