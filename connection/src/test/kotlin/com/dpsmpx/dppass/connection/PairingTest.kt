package com.dpsmpx.dppass.connection

import com.dpsmpx.dppass.diagnostics.DiagCode
import com.dpsmpx.dppass.diagnostics.Outcome
import kotlinx.coroutines.runBlocking
import java.io.InputStream
import java.io.OutputStream
import java.io.PipedInputStream
import java.io.PipedOutputStream
import java.security.KeyPairGenerator
import java.security.SecureRandom
import java.security.spec.ECGenParameterSpec
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicReference
import kotlin.concurrent.thread
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNotEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** Канал в одну сторону: что пишет одна сторона, читает другая. */
private class Pipe {
    val input = PipedInputStream(1 shl 16)
    val output = PipedOutputStream(input)
}

private val OFFER = Pairing.Offer(41234, "d-guest01", "p-test-0123456789", "Redmi")

/** Сопряжение устройства раздачи (D-56): код на обоих экранах, вход — только после двух подтверждений. */
class PairingTest {
    private val random = SecureRandom()

    private class Side(val code: AtomicReference<String?> = AtomicReference(null))

    /** Хозяин в своём потоке, гость — здесь; итог обоих. */
    private fun pair(
        hostSays: Boolean = true,
        guestSays: Boolean = true,
        issued: AtomicInteger = AtomicInteger(),
        host: Side = Side(),
        guest: Side = Side(),
    ): Pair<Outcome<Unit>, Outcome<Pairing.Offer>> {
        val toHost = Pipe()
        val toGuest = Pipe()
        val hostResult = AtomicReference<Outcome<Unit>>()
        val t = thread(isDaemon = true) {
            hostResult.set(
                runBlocking {
                    Pairing.host(toHost.input, toGuest.output, random, { c -> host.code.set(c); hostSays }) {
                        issued.incrementAndGet()
                        Outcome.Success(OFFER)
                    }
                },
            )
            toGuest.output.close()
        }
        val guestResult = runBlocking { Pairing.guest(toGuest.input, toHost.output, random) { c -> guest.code.set(c); guestSays } }
        toHost.output.close()
        t.join(10_000)
        return hostResult.get() to guestResult
    }

    @Test
    fun bothConfirmTheSameCodeAndGuestGetsTheOffer() {
        val issued = AtomicInteger()
        val host = Side()
        val guest = Side()
        val (h, g) = pair(issued = issued, host = host, guest = guest)
        assertIs<Outcome.Success<Unit>>(h)
        assertEquals(OFFER, g.valueOrNull())
        assertEquals(1, issued.get())
        val code = host.code.get()!!
        assertEquals(guest.code.get(), code, "один и тот же код на обоих экранах")
        assertTrue(code.length == Pairing.CODE_DIGITS && code.all(Char::isDigit), code)
    }

    @Test
    fun refusalOnEitherSideIssuesNothing() {
        for ((hostSays, guestSays) in listOf(false to true, true to false, false to false)) {
            val issued = AtomicInteger()
            val (h, g) = pair(hostSays, guestSays, issued)
            assertEquals(0, issued.get(), "вход не выдан: host=$hostSays guest=$guestSays")
            assertEquals(DiagCode.PAIRING_REFUSED, (g as Outcome.Failure).errors.single().code)
            assertEquals(DiagCode.PAIRING_REFUSED, (h as Outcome.Failure).errors.single().code)
        }
    }

    @Test
    fun keysSwappedInTheMiddleShowDifferentCodes() {
        // Подмена: посредник ведёт сопряжение с каждым своим ключом. Экраны показывают разные коды.
        val gToM = Pipe()
        val mToG = Pipe()
        val mToH = Pipe()
        val hToM = Pipe()
        val hostCode = AtomicReference<String>()
        val guestCode = AtomicReference<String>()
        val h = thread(isDaemon = true) { runBlocking { Pairing.host(mToH.input, hToM.output, random, { hostCode.set(it); true }) { Outcome.Success(OFFER) } } }
        val m = thread(isDaemon = true) {
            runBlocking {
                val stolen = Pairing.guest(hToM.input, mToH.output, random) { true }
                Pairing.host(gToM.input, mToG.output, random, { true }) { stolen }
            }
        }
        runBlocking { Pairing.guest(mToG.input, gToM.output, random) { guestCode.set(it); true } }
        h.join(10_000)
        m.join(10_000)
        assertNotEquals(hostCode.get(), guestCode.get(), "при подмене коды на экранах разные — пользователь видит это до выдачи входа")
    }

    @Test
    fun nonceNotMatchingTheCommitmentIsTampering() {
        // Хозяин закрепил одно число, а прислал другое — так подбирают код под гостя.
        val toHost = Pipe()
        val toGuest = Pipe()
        val fake = thread(isDaemon = true) {
            readFrame(toHost.input)
            val key = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair().public.encoded
            writeFrame(toGuest.output, 2, key)
            writeFrame(toGuest.output, 3, ByteArray(32).also(random::nextBytes))
            readFrame(toHost.input)
            writeFrame(toGuest.output, 5, ByteArray(16).also(random::nextBytes))
        }
        val g = runBlocking { Pairing.guest(toGuest.input, toHost.output, random) { error("код при подмене не показывается") } }
        fake.join(10_000)
        assertEquals(DiagCode.PAIRING_BROKEN, (g as Outcome.Failure).errors.single().code)
    }

    @Test
    fun foreignCurveAndForeignProtocolAreRefused() {
        val toHost = Pipe()
        val toGuest = Pipe()
        val p384 = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp384r1")) }.generateKeyPair().public.encoded
        writeFrame(toHost.output, 1, "DPPAIR1".toByteArray() + p384)
        val h = runBlocking { Pairing.host(toHost.input, toGuest.output, random, { error("не дошло") }) { error("не дошло") } }
        assertEquals(DiagCode.PAIRING_BROKEN, (h as Outcome.Failure).errors.single().code)

        // На порту — не DPpass: ответ не кадр ключа.
        val http = Pipe()
        http.output.write("HTTP/1.1 400 Bad Request\r\n\r\n".toByteArray())
        http.output.close()
        val g = runBlocking { Pairing.guest(http.input, Pipe().output, random) { error("не дошло") } }
        assertEquals(DiagCode.PAIRING_BROKEN, (g as Outcome.Failure).errors.single().code)
    }

    @Test
    fun tamperedOfferIsNotAccepted() {
        // Посредник без ключей пропускает кадры и портит зашифрованный вход: гость не примет.
        val gToM = Pipe()
        val mToG = Pipe()
        val mToH = Pipe()
        val hToM = Pipe()
        thread(isDaemon = true) { runBlocking { Pairing.host(mToH.input, hToM.output, random, { true }) { Outcome.Success(OFFER) } } }
        thread(isDaemon = true) { relay(gToM.input, mToH.output, tamper = false) }
        thread(isDaemon = true) { relay(hToM.input, mToG.output, tamper = true) }
        val g = runBlocking { Pairing.guest(mToG.input, gToM.output, random) { true } }
        assertEquals(DiagCode.PAIRING_BROKEN, (g as Outcome.Failure).errors.single().code)
        assertNull(g.valueOrNull())
    }

    // ---- кадры протокола: тип, длина (2 байта), данные ----

    private fun writeFrame(out: OutputStream, type: Int, payload: ByteArray) {
        out.write(byteArrayOf(type.toByte(), (payload.size shr 8).toByte(), payload.size.toByte()) + payload)
        out.flush()
    }

    private fun readFrame(input: InputStream): Pair<Int, ByteArray>? {
        val head = input.readNBytes(3)
        if (head.size < 3) return null
        val size = ((head[1].toInt() and 0xff) shl 8) or (head[2].toInt() and 0xff)
        return (head[0].toInt() and 0xff) to input.readNBytes(size)
    }

    private fun relay(from: InputStream, to: OutputStream, tamper: Boolean) {
        try {
            while (true) {
                val (type, body) = readFrame(from) ?: break
                if (tamper && type == 7) body[body.size - 1] = (body[body.size - 1].toInt() xor 1).toByte()
                writeFrame(to, type, body)
            }
        } catch (e: java.io.IOException) {
            // Другая сторона закончила: посреднику больше нечего пересылать.
        }
        runCatching { to.close() }
    }
}
