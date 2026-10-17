package com.dpsmpx.dppass.network

import com.dpsmpx.dppass.core.Clock
import java.io.EOFException
import java.io.IOException
import java.io.InputStream
import java.net.ConnectException
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.Inet4Address
import java.net.Inet6Address
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.NoRouteToHostException
import java.net.PortUnreachableException
import java.net.Socket
import java.net.SocketTimeoutException
import java.net.UnknownHostException
import java.security.SecureRandom
import javax.net.ssl.SSLException
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory

/**
 * Ориентир проб (D-60): имя, к которому идут DNS, TCP, TLS, QUIC и
 * крупная передача. [bulkPath] — адрес с заданным объёмом ответа; null —
 * крупная передача к этому ориентиру не мерится.
 */
data class Landmark(val host: String, val port: Int = 443, val bulkPath: String? = null)

/** Ориентиры по решениям D-60 и D-62; меняются только решением. */
object Landmarks {
    /** Из типичного белого списка (L9): отличает «внутрь можно, наружу нельзя» от «нельзя никуда». */
    val DOMESTIC: Landmark = Landmark("ya.ru")

    /** Сеть доставки, где наблюдалось ограничение 16 КБ (L4, L7), с адресом заданного объёма. */
    val FOREIGN: Landmark = Landmark("speed.cloudflare.com", bulkPath = "/__down?bytes=65536")

    /**
     * У другого поставщика, чем [FOREIGN] (D-62): закрыт один — довод L4,
     * закрыты оба при живом отечественном — белый список (L9). Только TCP,
     * TLS и QUIC: имя резолвит проба DNS первого, крупной передачи нет.
     */
    val FOREIGN_ALT: Landmark = Landmark("www.google.com")

    fun of(target: ProbeTarget): Landmark = when (target) {
        ProbeTarget.DOMESTIC -> DOMESTIC
        ProbeTarget.FOREIGN -> FOREIGN
        ProbeTarget.FOREIGN_ALT -> FOREIGN_ALT
    }
}

/**
 * Сеть, через которую идут пробы (D-60). На Android — сеть под туннелем:
 * её резолвер и сокеты, привязанные к ней; на JVM — система
 * ([SystemProbeNetwork]).
 */
interface ProbeNetwork {
    /** Адреса имени резолвером этой сети. Не резолвится — [UnknownHostException]. */
    fun resolve(host: String): List<InetAddress>

    /** Сокет TCP этой сети, ещё не соединённый. */
    fun tcpSocket(): Socket

    /** Сокет UDP этой сети. */
    fun udpSocket(): DatagramSocket

    /** Перехват страницей входа — по сведениям системы; null — система не знает. */
    fun captivePortal(): Boolean?
}

/** Сеть процесса на JVM (`cli`, тесты): системный резолвер; о странице входа не знает. */
object SystemProbeNetwork : ProbeNetwork {
    override fun resolve(host: String): List<InetAddress> = InetAddress.getAllByName(host).toList()

    override fun tcpSocket(): Socket = Socket()

    override fun udpSocket(): DatagramSocket = DatagramSocket()

    override fun captivePortal(): Boolean? = null
}

/** TLS поверх соединённого сокета с SNI [host]. В приложении — платформенный, с проверкой имени (T5). */
fun interface TlsLayer {
    fun wrap(socket: Socket, host: String, port: Int): Socket
}

/**
 * Платформенный TLS: сертификат проверяет система, имя — алгоритм
 * `HTTPS` (RFC 2818). Своего `TrustManager` и ослабления проверки нет (T5).
 */
object PlatformTls : TlsLayer {
    override fun wrap(socket: Socket, host: String, port: Int): Socket {
        val tls = (SSLSocketFactory.getDefault() as SSLSocketFactory).createSocket(socket, host, port, true) as SSLSocket
        tls.sslParameters = tls.sslParameters.apply { endpointIdentificationAlgorithm = "HTTPS" }
        tls.startHandshake()
        return tls
    }
}

/**
 * Пробы на настоящих сокетах (D-14, D-60): по одному запросу, без
 * повторов — повторы и залпы решает бюджет ([NetworkAssessor]). Исход —
 * наблюдение о сети, а не о сервере; адресов в нём нет.
 *
 * Блокирует поток: вызывать в фоне.
 */
class SocketProber(
    private val network: ProbeNetwork,
    private val clock: Clock,
    private val random: SecureRandom,
    private val landmarks: (ProbeTarget) -> Landmark = Landmarks::of,
    private val tls: TlsLayer = PlatformTls,
    /** Отдельный адрес UDP для тестов; null — порт ориентира. */
    private val udpPort: Int? = null,
    private val timeoutMillis: Int = TIMEOUT_MILLIS,
    private val bulkDeadlineMillis: Long = BULK_DEADLINE_MILLIS,
    /** Адрес не годится в ответ на публичное имя; в тестах ориентиры — на 127.0.0.1. */
    private val bogon: (InetAddress) -> Boolean = ::isBogon,
) : Prober {
    override suspend fun probe(request: ProbeRequest): ProbeResult {
        val landmark = landmarks(request.target)
        val started = clock.nowMillis()
        val (outcome, at) = when (request.kind) {
            ProbeKind.CAPTIVE -> captive()
            ProbeKind.DNS -> dns(landmark)
            ProbeKind.TCP -> connected(landmark) { it.close() }
            ProbeKind.TLS -> connected(landmark) { s -> tls.wrap(s, landmark.host, landmark.port).close() }
            ProbeKind.UDP -> udp(landmark)
            ProbeKind.BULK -> bulk(landmark)
        }
        val latency = if (outcome == ProbeOutcome.SUCCESS) ((at ?: clock.nowMillis()) - started).coerceAtLeast(1) else null
        return ProbeResult(request, outcome, latency)
    }

    /** Исход и, если он не в конце пробы, время, до которого мерится задержка. */
    private data class Done(val outcome: ProbeOutcome, val at: Long? = null)

    private fun captive(): Done = when (network.captivePortal()) {
        true -> Done(ProbeOutcome.REDIRECTED)
        false -> Done(ProbeOutcome.SUCCESS)
        null -> Done(ProbeOutcome.INCONCLUSIVE)
    }

    private fun dns(landmark: Landmark): Done {
        val addresses = try {
            network.resolve(landmark.host)
        } catch (e: UnknownHostException) {
            return Done(ProbeOutcome.UNREACHABLE)
        } catch (e: SecurityException) {
            return Done(ProbeOutcome.UNREACHABLE)
        }
        return when {
            addresses.isEmpty() -> Done(ProbeOutcome.UNREACHABLE)
            // Публичное имя в частный, служебный или нулевой адрес — подмена (L1).
            addresses.all(bogon) -> Done(ProbeOutcome.DNS_TAMPERED)
            else -> Done(ProbeOutcome.SUCCESS)
        }
    }

    /** Адрес ориентира: первый не служебный; имени нет — пути к ориентиру нет. */
    private fun address(landmark: Landmark): InetAddress? = try {
        network.resolve(landmark.host).firstOrNull { !bogon(it) }
    } catch (e: UnknownHostException) {
        null
    } catch (e: SecurityException) {
        null
    }

    private fun connected(landmark: Landmark, use: (Socket) -> Unit): Done {
        val address = address(landmark) ?: return Done(ProbeOutcome.UNREACHABLE)
        val socket = network.tcpSocket()
        return try {
            socket.connect(InetSocketAddress(address, landmark.port), timeoutMillis)
            socket.soTimeout = timeoutMillis
            use(socket)
            Done(ProbeOutcome.SUCCESS)
        } catch (e: IOException) {
            Done(failure(e))
        } finally {
            closeQuietly(socket)
        }
    }

    private fun udp(landmark: Landmark): Done {
        val address = address(landmark) ?: return Done(ProbeOutcome.UNREACHABLE)
        val packet = QuicInitial.build(landmark.host, random)
        val socket = network.udpSocket()
        return try {
            socket.soTimeout = timeoutMillis
            socket.connect(InetSocketAddress(address, udpPort ?: landmark.port))
            socket.send(DatagramPacket(packet.bytes, packet.bytes.size))
            val buffer = ByteArray(RESPONSE_BYTES)
            val deadline = clock.nowMillis() + timeoutMillis
            do {
                val reply = DatagramPacket(buffer, buffer.size)
                socket.receive(reply)
                if (QuicInitial.isResponse(reply.data, reply.length, packet.sourceId)) return Done(ProbeOutcome.SUCCESS)
                // Чужой пакет — ждём дальше, но не дольше срока пробы.
            } while (clock.nowMillis() < deadline)
            Done(ProbeOutcome.TIMEOUT)
        } catch (e: PortUnreachableException) {
            Done(ProbeOutcome.REFUSED)
        } catch (e: IOException) {
            Done(failure(e))
        } finally {
            socket.close()
        }
    }

    /**
     * Крупная передача (L4, L7): HTTPS-запрос [Landmark.bulkPath] и чтение
     * до [BULK_SUCCESS_BYTES]. Ответ встал после начала — «замерзание»;
     * ответ не 2xx — проба ничего не сказала о сети.
     */
    private fun bulk(landmark: Landmark): Done {
        val path = landmark.bulkPath ?: return Done(ProbeOutcome.INCONCLUSIVE)
        val address = address(landmark) ?: return Done(ProbeOutcome.UNREACHABLE)
        val socket = network.tcpSocket()
        var received = 0L
        var firstByteAt: Long? = null
        return try {
            socket.connect(InetSocketAddress(address, landmark.port), timeoutMillis)
            socket.soTimeout = timeoutMillis
            val s = tls.wrap(socket, landmark.host, landmark.port)
            val request = "GET $path HTTP/1.1\r\nHost: ${landmark.host}\r\nUser-Agent: $USER_AGENT\r\nAccept: */*\r\nConnection: close\r\n\r\n"
            s.getOutputStream().apply {
                write(request.toByteArray(Charsets.US_ASCII))
                flush()
            }
            val input = s.getInputStream()
            val status = statusLine(input)
            firstByteAt = clock.nowMillis()
            received = status.length.toLong()
            if (!status.matches(Regex("HTTP/1\\.[01] 2\\d\\d.*"))) return Done(ProbeOutcome.INCONCLUSIVE)
            val deadline = clock.nowMillis() + bulkDeadlineMillis
            val buffer = ByteArray(8192)
            while (received < BULK_SUCCESS_BYTES) {
                if (clock.nowMillis() >= deadline) return Done(ProbeOutcome.STALLED)
                val n = input.read(buffer)
                if (n < 0) return Done(ProbeOutcome.STALLED)
                received += n
            }
            Done(ProbeOutcome.SUCCESS, firstByteAt)
        } catch (e: SocketTimeoutException) {
            Done(if (received > 0) ProbeOutcome.STALLED else ProbeOutcome.TIMEOUT)
        } catch (e: IOException) {
            // Сброс посреди ответа — данные встали на объёме; до ответа — отказ соединения.
            Done(if (received > 0) ProbeOutcome.STALLED else failure(e))
        } finally {
            closeQuietly(socket)
        }
    }

    /** Строка статуса HTTP — до перевода строки, не длиннее предела. */
    private fun statusLine(input: InputStream): String {
        val line = StringBuilder()
        while (line.length < STATUS_LIMIT) {
            val c = input.read()
            if (c < 0) throw EOFException("ответ оборвался до строки статуса")
            if (c == '\n'.code) break
            if (c != '\r'.code) line.append(c.toChar())
        }
        return line.toString()
    }

    private fun failure(e: IOException): ProbeOutcome = when (e) {
        is SocketTimeoutException -> ProbeOutcome.TIMEOUT
        is ConnectException -> ProbeOutcome.REFUSED
        is NoRouteToHostException -> ProbeOutcome.UNREACHABLE
        // Рукопожатие сорвано: сброс, чужой сертификат или имя — для пробы одно и то же.
        is SSLException, is EOFException -> ProbeOutcome.RESET
        else -> if (e.message?.contains("reset", ignoreCase = true) == true) ProbeOutcome.RESET else ProbeOutcome.UNREACHABLE
    }

    private fun closeQuietly(socket: Socket) {
        try {
            socket.close()
        } catch (e: IOException) {
            // закрытие неудачного сокета — не событие
        }
    }

    companion object {
        const val TIMEOUT_MILLIS: Int = 5_000
        const val BULK_DEADLINE_MILLIS: Long = 10_000

        /** Порог «крупной передачи» (`ProbeKind.BULK`): больше 16–20 КБ ограничения L4/L7. */
        const val BULK_SUCCESS_BYTES: Long = 32 * 1024

        /** Собственный `User-Agent` без версии: одинаковый у всех установок (D-12, D-60). */
        const val USER_AGENT: String = "DPpass"
        private const val RESPONSE_BYTES = 2048
        private const val STATUS_LIMIT = 256

        /** Частный, служебный, нулевой или групповой адрес — не ответ на публичное имя. */
        fun isBogon(a: InetAddress): Boolean = when (a) {
            is Inet4Address -> {
                val b = a.address
                val first = b[0].toInt() and 0xff
                val second = b[1].toInt() and 0xff
                a.isAnyLocalAddress || a.isLoopbackAddress || a.isLinkLocalAddress || a.isSiteLocalAddress || a.isMulticastAddress ||
                    first == 0 || (first == 100 && second in 64..127) || first >= 240
            }
            is Inet6Address -> a.isAnyLocalAddress || a.isLoopbackAddress || a.isLinkLocalAddress || a.isSiteLocalAddress ||
                a.isMulticastAddress || (a.address[0].toInt() and 0xfe) == 0xfc
            else -> true
        }
    }
}
