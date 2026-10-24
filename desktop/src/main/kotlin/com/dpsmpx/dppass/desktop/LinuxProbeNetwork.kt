package com.dpsmpx.dppass.desktop

import com.dpsmpx.dppass.core.IpAddress
import com.dpsmpx.dppass.diagnostics.DiagCode
import com.dpsmpx.dppass.diagnostics.Diagnostic
import com.dpsmpx.dppass.network.NetworkType
import com.dpsmpx.dppass.network.ProbeNetwork
import java.io.File
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.Socket
import java.net.UnknownHostException
import java.nio.channels.Channel
import java.nio.channels.DatagramChannel
import java.nio.channels.SocketChannel

/**
 * Сеть проб проверки на ПК (D-79): мимо туннеля, как сокеты ядра (D-74,
 * T4). Сокет пробы получает метку `SO_MARK` до соединения, и правило метки
 * ведёт его в таблицу `main`. Имена резолвит резолвер моста, тоже с меткой
 * ([LinuxNative.nativeResolve]): запрос JVM на порт 53 правило DNS увело бы
 * в ядро. Без метки проба мерила бы сервер, а не сеть (D-05), поэтому метка
 * не встала — сокет закрыт, и проба отказывает, а не идёт в туннель.
 */
class LinuxProbeNetwork(
    /** Поставить метку на fd: 0 или −errno; null — метка не нужна: без `CAP_NET_ADMIN` туннеля нет. */
    private val mark: ((Int) -> Int)?,
    private val resolver: (String) -> List<InetAddress>,
) : ProbeNetwork {
    override fun resolve(host: String): List<InetAddress> = resolver(host)

    override fun tcpSocket(): Socket = SocketChannel.open().also(::marked).socket()

    override fun udpSocket(): DatagramSocket = DatagramChannel.open().also(::marked).socket()

    /** Страницу входа на ПК система DPpass не сообщает. */
    override fun captivePortal(): Boolean? = null

    /**
     * Метка ставится — проверку можно начинать; иначе причина. Проверяется до
     * проб: отказ одной пробы прочитался бы как свойство сети.
     */
    fun ready(): Diagnostic? {
        val m = mark ?: return null
        DatagramChannel.open().use { ch ->
            val fd = fdOf(ch) ?: return unavailable("не узнать fd сокета JDK (нужен флаг запуска --add-exports java.base/sun.nio.ch)")
            val err = m(fd)
            return if (err == 0) null else unavailable("метка SO_MARK не поставилась (errno ${-err})")
        }
    }

    private fun marked(ch: Channel) {
        val m = mark ?: return
        val fd = fdOf(ch)
        // Не вышло — закрыть: соединение закрытого сокета — отказ пробы, а не путь в туннель.
        if (fd == null || m(fd) != 0) ch.close()
    }

    private fun unavailable(why: String): Diagnostic = Diagnostic.error(
        DiagCode.NETWORK_CHECK_UNAVAILABLE,
        "проверке сети не пустить пробы мимо туннеля: $why — через туннель она мерила бы сервер, а не сеть",
    )

    companion object {
        /** Срок резолва одного имени — как у пробы TCP. */
        const val RESOLVE_TIMEOUT_MILLIS: Int = 5_000

        /**
         * fd канала JDK — `sun.nio.ch.SelChImpl.getFDVal`: другого пути у JVM
         * нет. Пакет открыт флагом запуска (`desktop/build.gradle.kts`); без
         * него — null.
         */
        fun fdOf(channel: Channel): Int? = try {
            Class.forName("sun.nio.ch.SelChImpl").getMethod("getFDVal").invoke(channel) as? Int
        } catch (e: ReflectiveOperationException) {
            null
        } catch (e: SecurityException) {
            null
        }

        /** Ответ [LinuxNative.nativeResolve] → адреса; отказ — [UnknownHostException] с текстом моста. */
        fun parseResolve(host: String, reply: ByteArray): List<InetAddress> {
            if (reply.isEmpty()) throw UnknownHostException("$host: мост не ответил")
            val text = String(reply, 1, reply.size - 1, Charsets.UTF_8)
            if (reply[0].toInt() != 0) throw UnknownHostException("$host: $text")
            // Адрес — литерал IP от моста: байты, без второго резолва (T4).
            return text.lines().filter { it.isNotBlank() }.map { a ->
                IpAddress.parse(a)?.let { InetAddress.getByAddress(it.toBytes()) } ?: throw UnknownHostException("$host: мост вернул не адрес «$a»")
            }
        }
    }
}

/**
 * Сеть ПК под туннелем (D-79): маршрут по умолчанию таблицы `main` — туда
 * идут сокеты с меткой. Из `/proc/net/route` — интерфейс и шлюз с наименьшей
 * метрикой; тип — по интерфейсу. Ключ сети для памяти режима (D-64) —
 * интерфейс и шлюз: другой Wi-Fi — другая сеть.
 */
data class LinuxNetwork(val iface: String, val gateway: String, val type: NetworkType) {
    /** Непрозрачный ключ для `RegimeMemory`; в журнал не идёт. */
    val key: Long get() = "$iface|$gateway".hashCode().toLong()

    companion object {
        /** Сеть сейчас; null — маршрута по умолчанию нет. */
        fun current(): LinuxNetwork? = try {
            parse(File("/proc/net/route").readText()) { File("/sys/class/net/$it/wireless").isDirectory }
        } catch (e: java.io.IOException) {
            null
        }

        /** Маршрут по умолчанию из текста `/proc/net/route` — наименьшая метрика; [wireless] — интерфейс беспроводной. */
        fun parse(route: String, wireless: (String) -> Boolean): LinuxNetwork? = route.lines().drop(1)
            .map { it.trim().split(Regex("\\s+")) }
            // Поля: интерфейс, назначение, шлюз, флаги, …, метрика (6), маска (7).
            .filter { f -> f.size >= 8 && f[1] == "00000000" && f[7] == "00000000" }
            .minByOrNull { f -> f[6].toLongOrNull() ?: Long.MAX_VALUE }
            ?.let { f -> LinuxNetwork(f[0], f[2], type(f[0], wireless(f[0]))) }

        /** Тип по интерфейсу: беспроводной — Wi-Fi, `ww*` — модем, `en*`/`eth*` — провод. */
        fun type(iface: String, wireless: Boolean): NetworkType = when {
            wireless -> NetworkType.WIFI
            iface.startsWith("ww") -> NetworkType.MOBILE
            iface.startsWith("en") || iface.startsWith("eth") -> NetworkType.ETHERNET
            else -> NetworkType.OTHER
        }
    }
}
