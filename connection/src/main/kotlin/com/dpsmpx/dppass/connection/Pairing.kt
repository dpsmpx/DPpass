package com.dpsmpx.dppass.connection

import com.dpsmpx.dppass.core.Json
import com.dpsmpx.dppass.core.JsonNumber
import com.dpsmpx.dppass.core.JsonObject
import com.dpsmpx.dppass.core.JsonParseException
import com.dpsmpx.dppass.core.JsonString
import com.dpsmpx.dppass.diagnostics.DiagCode
import com.dpsmpx.dppass.diagnostics.Outcome
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.security.GeneralSecurityException
import java.security.KeyFactory
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.PrivateKey
import java.security.PublicKey
import java.security.SecureRandom
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.security.spec.X509EncodedKeySpec
import javax.crypto.Cipher
import javax.crypto.KeyAgreement
import javax.crypto.Mac
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * Сопряжение устройства раздачи без ввода пароля (D-56). Раздающий
 * телефон («хозяин») выдаёт подключающемуся («гостю») свой вход раздачи —
 * только после того, как пользователь на обоих экранах подтвердил, что
 * код совпадает.
 *
 * Ход — как сравнение чисел при сопряжении Bluetooth (Secure Simple
 * Pairing, numeric comparison), на стандартных примитивах JDK и Android:
 * 1. гость → хозяин: приветствие и открытый ключ P-256 гостя;
 * 2. хозяин → гость: свой открытый ключ и обязательство
 *    `HMAC(Nh, ключ хозяина ‖ ключ гостя)` — случайное Nh выбрано и
 *    закреплено до того, как хозяин увидит Ng;
 * 3. гость → хозяин: Ng; хозяин → гость: Nh; гость сверяет обязательство;
 * 4. код — 6 цифр из `SHA-256(ключи ‖ Ng ‖ Nh)`: подмена ключей в
 *    середине даёт разные коды на экранах (угадать — 1 из 10⁶ за попытку);
 * 5. оба подтверждают; хозяин шифрует вход ключом из ECDH (HKDF-SHA256,
 *    AES-256-GCM, данные шага — в связанных данных) и отправляет.
 *
 * Здесь только разговор с потоками: сокеты, привязанные к сети раздачи,
 * окно в две минуты и экран с кодом — у оболочки. Функции блокируют поток
 * чтением — вызывать на потоке ввода-вывода.
 */
object Pairing {
    /** Порт сопряжения: открыт только по нажатию, не дольше [WINDOW_MILLIS] и только на адресах раздачи. */
    const val PORT: Int = 47521
    const val WINDOW_MILLIS: Long = 120_000
    const val CODE_DIGITS: Int = 6

    /** Что хозяин отдаёт гостю: вход раздачи и имя, под которым гость покажет устройство. */
    data class Offer(val port: Int, val user: String, val password: String, val name: String)

    /**
     * Ход хозяина: [confirm] — решение пользователя, увидевшего код (можно
     * ждать); [issue] — выдать вход, только когда подтвердили оба.
     */
    @Throws(IOException::class)
    suspend fun host(
        input: InputStream,
        output: OutputStream,
        random: SecureRandom,
        confirm: suspend (String) -> Boolean,
        issue: suspend () -> Outcome<Offer>,
    ): Outcome<Unit> {
        val hello = receive(input, HELLO) ?: return broken("нет приветствия сопряжения")
        if (!hello.startsWith(MAGIC)) return broken("на порту сопряжения — не DPpass")
        val guestKeyBytes = hello.copyOfRange(MAGIC.size, hello.size)
        val guestKey = publicKey(guestKeyBytes) ?: return broken("ключ гостя — не P-256")
        val own = keyPair(random)
        val ownKey = own.public.encoded
        val nonceHost = ByteArray(NONCE).also(random::nextBytes)
        val commitment = hmac(nonceHost, MAGIC + ownKey + guestKeyBytes)
        send(output, KEY, ownKey)
        send(output, COMMIT, commitment)
        val nonceGuest = receive(input, NONCE_GUEST)?.takeIf { it.size == NONCE } ?: return broken("нет случайного числа гостя")
        send(output, NONCE_HOST, nonceHost)
        val transcript = Transcript(guestKeyBytes, ownKey, nonceGuest, nonceHost, commitment)
        val secret = agree(own.private, guestKey) ?: return broken("общий ключ не получен")
        if (!confirm(transcript.code())) {
            sendLast(output, REFUSE)
            return refused("код не подтверждён на этом телефоне")
        }
        if (receive(input, CONFIRMED) == null) return refused("код не подтверждён на другом телефоне")
        val offer = when (val o = issue()) {
            is Outcome.Failure -> {
                sendLast(output, REFUSE)
                return o
            }
            is Outcome.Success -> o.value
        }
        send(output, OFFER, seal(transcript.key(secret), transcript.aad(), encode(offer), random))
        return Outcome.Success(Unit)
    }

    /** Ход гостя: [confirm] — решение пользователя, увидевшего код. Итог — вход раздачи хозяина. */
    @Throws(IOException::class)
    suspend fun guest(input: InputStream, output: OutputStream, random: SecureRandom, confirm: suspend (String) -> Boolean): Outcome<Offer> {
        val own = keyPair(random)
        val ownKey = own.public.encoded
        send(output, HELLO, MAGIC + ownKey)
        val hostKeyBytes = receive(input, KEY) ?: return broken("нет ключа раздающего телефона")
        val hostKey = publicKey(hostKeyBytes) ?: return broken("ключ раздающего телефона — не P-256")
        val commitment = receive(input, COMMIT)?.takeIf { it.size == HASH } ?: return broken("нет обязательства раздающего телефона")
        val nonceGuest = ByteArray(NONCE).also(random::nextBytes)
        send(output, NONCE_GUEST, nonceGuest)
        val nonceHost = receive(input, NONCE_HOST)?.takeIf { it.size == NONCE } ?: return broken("нет случайного числа раздающего телефона")
        // Число не то, что было закреплено: раздающий подбирал код под наш — подмена.
        if (!MessageDigest.isEqual(hmac(nonceHost, MAGIC + hostKeyBytes + ownKey), commitment)) {
            return broken("обязательство не сошлось — возможна подмена; сопряжение прервано")
        }
        val transcript = Transcript(ownKey, hostKeyBytes, nonceGuest, nonceHost, commitment)
        val secret = agree(own.private, hostKey) ?: return broken("общий ключ не получен")
        if (!confirm(transcript.code())) {
            sendLast(output, REFUSE)
            return refused("код не подтверждён на этом телефоне")
        }
        // Раздающий мог уже отказать и закрыть соединение: его отказ всё равно прочитается ниже.
        sendLast(output, CONFIRMED)
        val (type, body) = receiveAny(input) ?: return refused("раздающий телефон закрыл сопряжение")
        return when (type) {
            REFUSE -> refused("код не подтверждён на раздающем телефоне")
            OFFER -> open(transcript.key(secret), transcript.aad(), body)?.let(::decode)?.let { Outcome.Success(it) }
                ?: broken("вход не расшифрован — возможна подмена")
            else -> broken("неожиданный ответ раздающего телефона")
        }
    }

    /** Данные сопряжения, общие для обеих сторон: из них — код, ключ и связанные данные шифра. */
    private class Transcript(val guestKey: ByteArray, val hostKey: ByteArray, val nonceGuest: ByteArray, val nonceHost: ByteArray, val commitment: ByteArray) {
        private val digest = sha256(MAGIC, guestKey, hostKey, nonceGuest, nonceHost)

        fun code(): String {
            val v = ((digest[0].toLong() and 0xff) shl 24) or ((digest[1].toLong() and 0xff) shl 16) or
                ((digest[2].toLong() and 0xff) shl 8) or (digest[3].toLong() and 0xff)
            return (v % CODE_SPACE).toString().padStart(CODE_DIGITS, '0')
        }

        fun key(secret: ByteArray): ByteArray = hkdf(secret, digest, INFO)

        fun aad(): ByteArray = sha256(digest, commitment)
    }

    // ---- кадры: тип, длина (2 байта), данные ----

    private fun send(out: OutputStream, type: Int, payload: ByteArray) {
        require(payload.size <= MAX_FRAME)
        out.write(byteArrayOf(type.toByte(), (payload.size shr 8).toByte(), payload.size.toByte()) + payload)
        out.flush()
    }

    /** Решение стороны; другая сторона могла уже закрыть соединение — тогда сказать некому. */
    private fun sendLast(out: OutputStream, type: Int) {
        try {
            send(out, type, ByteArray(0))
        } catch (e: IOException) {
            // Соединение закрыто: итог определит то, что другая сторона успела прислать.
        }
    }

    /** Кадр ожидаемого типа; другой тип, обрыв или кадр больше предела — null. */
    private fun receive(input: InputStream, type: Int): ByteArray? = receiveAny(input)?.takeIf { it.first == type }?.second

    private fun receiveAny(input: InputStream): Pair<Int, ByteArray>? {
        val head = readExactly(input, 3) ?: return null
        val size = ((head[1].toInt() and 0xff) shl 8) or (head[2].toInt() and 0xff)
        if (size > MAX_FRAME) return null
        val body = readExactly(input, size) ?: return null
        return (head[0].toInt() and 0xff) to body
    }

    private fun readExactly(input: InputStream, n: Int): ByteArray? {
        val out = ByteArray(n)
        var got = 0
        while (got < n) {
            val r = input.read(out, got, n - got)
            if (r < 0) return null
            got += r
        }
        return out
    }

    // ---- примитивы ----

    private val P256: ECParameterSpec by lazy { (keyPair(SecureRandom()).public as ECPublicKey).params }

    private fun keyPair(random: SecureRandom): KeyPair =
        KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1"), random) }.generateKeyPair()

    /** Открытый ключ из X.509 — только P-256 (та же кривая, точка, порядок): чужая кривая — отказ. */
    private fun publicKey(encoded: ByteArray): PublicKey? = try {
        (KeyFactory.getInstance("EC").generatePublic(X509EncodedKeySpec(encoded)) as? ECPublicKey)?.takeIf { k ->
            val p = k.params
            p.curve == P256.curve && p.generator == P256.generator && p.order == P256.order && p.cofactor == P256.cofactor
        }
    } catch (e: GeneralSecurityException) {
        null
    }

    private fun agree(own: PrivateKey, other: PublicKey): ByteArray? = try {
        KeyAgreement.getInstance("ECDH").apply {
            init(own)
            doPhase(other, true)
        }.generateSecret()
    } catch (e: GeneralSecurityException) {
        null
    }

    private fun hmac(key: ByteArray, data: ByteArray): ByteArray =
        Mac.getInstance("HmacSHA256").apply { init(SecretKeySpec(key, "HmacSHA256")) }.doFinal(data)

    private fun sha256(vararg parts: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").apply { parts.forEach(::update) }.digest()

    /** HKDF-SHA256 (RFC 5869) на 32 байта: извлечение и один блок расширения. */
    private fun hkdf(ikm: ByteArray, salt: ByteArray, info: ByteArray): ByteArray = hmac(hmac(salt, ikm), info + byteArrayOf(1))

    private fun seal(key: ByteArray, aad: ByteArray, plain: ByteArray, random: SecureRandom): ByteArray {
        val iv = ByteArray(IV).also(random::nextBytes)
        val c = Cipher.getInstance("AES/GCM/NoPadding").apply {
            init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(TAG_BITS, iv))
            updateAAD(aad)
        }
        return iv + c.doFinal(plain)
    }

    /** Расшифровать; подделка, чужой ключ или чужие данные шага — null. */
    private fun open(key: ByteArray, aad: ByteArray, sealed: ByteArray): ByteArray? {
        if (sealed.size <= IV) return null
        return try {
            Cipher.getInstance("AES/GCM/NoPadding").apply {
                init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(TAG_BITS, sealed.copyOfRange(0, IV)))
                updateAAD(aad)
            }.doFinal(sealed, IV, sealed.size - IV)
        } catch (e: GeneralSecurityException) {
            null
        }
    }

    private fun encode(o: Offer): ByteArray = Json.write(
        Json.obj("port" to Json.num(o.port), "user" to Json.str(o.user), "password" to Json.str(o.password), "name" to Json.str(o.name)),
        pretty = false,
    ).toByteArray(Charsets.UTF_8)

    private fun decode(bytes: ByteArray): Offer? {
        val o = try {
            Json.parse(String(bytes, Charsets.UTF_8)) as? JsonObject
        } catch (e: JsonParseException) {
            null
        } ?: return null
        val port = (o["port"] as? JsonNumber)?.toIntOrNull()?.takeIf { it in 1..65535 } ?: return null
        val user = (o["user"] as? JsonString)?.value?.takeIf { it.isNotEmpty() } ?: return null
        val password = (o["password"] as? JsonString)?.value?.takeIf { it.isNotEmpty() } ?: return null
        val name = (o["name"] as? JsonString)?.value ?: return null
        return Offer(port, user, password, name)
    }

    private fun ByteArray.startsWith(prefix: ByteArray): Boolean = size >= prefix.size && prefix.indices.all { this[it] == prefix[it] }

    private fun broken(why: String): Outcome<Nothing> = Outcome.failure(DiagCode.PAIRING_BROKEN, why)

    private fun refused(why: String): Outcome<Nothing> = Outcome.failure(DiagCode.PAIRING_REFUSED, why)

    private val MAGIC = "DPPAIR2".toByteArray(Charsets.US_ASCII)
    private val INFO = "dppass-pair-v1 offer".toByteArray(Charsets.US_ASCII)
    private const val CODE_SPACE = 1_000_000L
    private const val NONCE = 16
    private const val HASH = 32
    private const val IV = 12
    private const val TAG_BITS = 128
    private const val MAX_FRAME = 1024

    private const val HELLO = 1
    private const val KEY = 2
    private const val COMMIT = 3
    private const val NONCE_GUEST = 4
    private const val NONCE_HOST = 5
    private const val CONFIRMED = 6
    private const val OFFER = 7
    private const val REFUSE = 8
}
