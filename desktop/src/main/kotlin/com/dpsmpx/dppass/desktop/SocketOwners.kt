package com.dpsmpx.dppass.desktop

import com.dpsmpx.dppass.connection.ConnectionOwners
import com.dpsmpx.dppass.core.Clock
import com.dpsmpx.dppass.core.IpAddress
import com.dpsmpx.dppass.engine.ConnNetwork
import com.dpsmpx.dppass.engine.EngineConnection
import com.dpsmpx.dppass.engine.InboundKind
import java.io.File
import java.io.IOException
import java.nio.file.Files

/**
 * Сокет системы и его процесс (D-106). Адреса — как в снимке ядра:
 * `адрес:порт`, IPv6 — в квадратных скобках; [remote] у UDP нет.
 */
data class OwnedSocket(val network: ConnNetwork, val local: String, val remote: String?, val owner: String)

/**
 * Процесс у соединения на ПК (D-106): соединение ядра — это сокет программы
 * с адресом источника из снимка (адрес TUN или 127.0.0.1 у локального
 * прокси) и адресом назначения. Таблица сокетов системы читается не чаще
 * раза в [refreshMillis] и только когда есть кого искать: на Linux — это
 * обход `/proc`. Раздача (другое устройство) — не узнать.
 */
class SocketOwners(
    private val read: () -> List<OwnedSocket>?,
    private val clock: Clock = Clock.MONOTONIC,
    private val refreshMillis: Long = 1_000,
) : ConnectionOwners {
    private var table: Map<Key, String> = emptyMap()
    private var local: Map<Pair<ConnNetwork, String>, String> = emptyMap()
    private var readAt = Long.MIN_VALUE

    private data class Key(val network: ConnNetwork, val local: String, val remote: String?)

    @Synchronized
    override fun owner(c: EngineConnection): String? {
        if (c.inboundKind == InboundKind.SHARE || c.source.isEmpty()) return null
        find(c)?.let { return it }
        val now = clock.nowMillis()
        if (readAt != Long.MIN_VALUE && now - readAt < refreshMillis) return null
        readAt = now
        val sockets = read() ?: return null
        table = sockets.associate { Key(it.network, normal(it.local), it.remote?.let(::normal)) to it.owner }
        local = sockets.associate { (it.network to normal(it.local)) to it.owner }
        return find(c)
    }

    private fun find(c: EngineConnection): String? {
        val src = normal(c.source)
        if (c.network == ConnNetwork.TCP) table[Key(c.network, src, normal(c.target))]?.let { return it }
        local[c.network to src]?.let { return it }
        // UDP без connect — на любом адресе своего порта.
        if (c.network != ConnNetwork.UDP) return null
        val port = src.substring(src.lastIndexOf(':'))
        return local[c.network to "0.0.0.0$port"] ?: local[c.network to "[::]$port"]
    }

    companion object {
        /** Одна запись адреса: IPv4 в IPv6 (`::ffff:a.b.c.d`) — как IPv4, IPv6 — каноничной формой. */
        fun normal(addrPort: String): String {
            val i = addrPort.lastIndexOf(':')
            if (i <= 0) return addrPort
            val host = addrPort.substring(0, i).removePrefix("[").removeSuffix("]")
            val ip = IpAddress.parse(host) ?: return addrPort
            val v4 = ip.toBytes().let { b ->
                if (b.size == 16 && b.take(10).all { it == 0.toByte() } && b[10] == 0xff.toByte() && b[11] == 0xff.toByte()) {
                    IpAddress.of(b.copyOfRange(12, 16))
                } else {
                    null
                }
            }
            val shown = v4 ?: ip
            val text = shown.toString()
            return if (':' in text) "[$text]${addrPort.substring(i)}" else "$text${addrPort.substring(i)}"
        }
    }
}

/**
 * Сокеты Linux (D-106) из `/proc`: таблицы `net/tcp`, `tcp6`, `udp`, `udp6`
 * — свой адрес, адрес собеседника и номер inode; процесс — тот, у кого среди
 * `fd` есть `socket:[inode]`, имя — `comm`. Чужие процессы (другого
 * пользователя, root) `/proc` не показывает — у таких сокетов процесса нет.
 */
object LinuxSockets {
    fun read(proc: File = File("/proc")): List<OwnedSocket>? {
        val inodes = HashMap<Long, Triple<ConnNetwork, String, String?>>()
        for ((name, network) in TABLES) {
            val lines = try {
                File(proc, "net/$name").readLines()
            } catch (e: IOException) {
                continue
            }
            for (line in lines.drop(1)) parseLine(line, network)?.let { (inode, sock) -> if (inode != 0L) inodes[inode] = sock }
        }
        if (inodes.isEmpty()) return null
        val out = ArrayList<OwnedSocket>()
        val pids = proc.listFiles { f -> f.name.all(Char::isDigit) }.orEmpty()
        for (pid in pids) {
            val fds = File(pid, "fd").listFiles() ?: continue
            var comm: String? = null
            for (fd in fds) {
                val link = try {
                    Files.readSymbolicLink(fd.toPath()).toString()
                } catch (e: IOException) {
                    continue
                } catch (e: UnsupportedOperationException) {
                    continue
                }
                if (!link.startsWith("socket:[")) continue
                val inode = link.removePrefix("socket:[").removeSuffix("]").toLongOrNull() ?: continue
                val (network, local, remote) = inodes[inode] ?: continue
                val name = comm ?: (runCatching { File(pid, "comm").readText().trim() }.getOrNull()?.ifEmpty { null } ?: pid.name).also { comm = it }
                out += OwnedSocket(network, local, remote, name)
            }
        }
        return out
    }

    /**
     * Строка таблицы: `sl local rem st … inode`. Адрес — шестнадцатеричный:
     * IPv4 — одно 32-битное слово, IPv6 — четыре, каждое младшим байтом
     * вперёд; порт — старшим вперёд. У UDP собеседник обычно нулевой — нет.
     */
    fun parseLine(line: String, network: ConnNetwork): Pair<Long, Triple<ConnNetwork, String, String?>>? {
        val f = line.trim().split(Regex("\\s+"))
        if (f.size < 10) return null
        val local = addr(f[1]) ?: return null
        val remote = addr(f[2])
        val inode = f[9].toLongOrNull() ?: return null
        val peer = remote?.takeUnless { network == ConnNetwork.UDP && it.endsWith(":0") }
        return inode to Triple(network, local, peer)
    }

    private fun addr(hex: String): String? {
        val (a, p) = hex.split(':').takeIf { it.size == 2 }?.let { it[0] to it[1] } ?: return null
        val port = p.toIntOrNull(16) ?: return null
        if (a.length != 8 && a.length != 32) return null
        val bytes = ByteArray(a.length / 2)
        for (w in 0 until a.length / 8) {
            val word = a.substring(w * 8, w * 8 + 8).toLongOrNull(16) ?: return null
            for (k in 0 until 4) bytes[w * 4 + k] = (word shr (8 * k)).toByte()
        }
        return SocketOwners.normal("${if (bytes.size == 16) "[" + IpAddress.of(bytes) + "]" else IpAddress.of(bytes).toString()}:$port")
    }

    private val TABLES = listOf("tcp" to ConnNetwork.TCP, "tcp6" to ConnNetwork.TCP, "udp" to ConnNetwork.UDP, "udp6" to ConnNetwork.UDP)
}

/** Сокеты Windows (D-106) — ответ моста ([WindowsNative.nativeSocketOwners]). */
object WindowsSockets {
    /** Статус первым байтом, затем строки: сеть, свой адрес, собеседник, номер и имя процесса; отказ — null. */
    fun parse(answer: ByteArray): List<OwnedSocket>? {
        if (answer.isEmpty() || answer[0].toInt() != 0) return null
        return answer.decodeToString(1, answer.size).lineSequence().mapNotNull { line ->
            val f = line.split('\t')
            if (f.size != 5) return@mapNotNull null
            val network = when (f[0]) {
                "tcp" -> ConnNetwork.TCP
                "udp" -> ConnNetwork.UDP
                else -> return@mapNotNull null
            }
            val owner = f[4].ifEmpty { "pid ${f[3]}" }
            OwnedSocket(network, f[1], f[2].ifEmpty { null }, owner)
        }.toList()
    }
}
