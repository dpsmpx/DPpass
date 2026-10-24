package com.dpsmpx.dppass.desktop

import com.dpsmpx.dppass.core.IpAddress
import com.dpsmpx.dppass.engine.ShareSpec
import java.net.Inet4Address
import java.net.NetworkInterface
import java.net.SocketException

/**
 * Интерфейсы раздачи ПК (D-84, к D-51): только общие сети NetworkManager —
 * соединения с `ipv4.method shared` («Точка доступа» Wi-Fi, «Общий доступ
 * с другими компьютерами» у проводного соединения). Что раздаёт — говорит
 * сам NetworkManager (`nmcli`), а не признаки интерфейса: второй провод
 * или Wi-Fi к другому роутеру выглядит так же, как раздача, и вход прокси
 * встал бы в чужую сеть.
 *
 * Ошибка в сторону «не раздавать»: нет `nmcli`, NetworkManager не ответил,
 * вывод не разобран — интерфейсов раздачи нет. Интерфейс маршрута по
 * умолчанию — сеть «вверх по течению» — не раздаётся, что бы ни сказал
 * NetworkManager.
 */
class LinuxShareInterfaces(
    private val nmcli: (List<String>) -> CommandResult = { SystemCommand.run(NMCLI_BINARIES, "nmcli (NetworkManager)", it, NMCLI_TIMEOUT_SECONDS) },
    private val interfaces: () -> List<Iface>? = ::systemInterfaces,
    private val upstream: () -> String? = { LinuxNetwork.current()?.iface },
) {
    /** Что известно об интерфейсе: поднят ли и его IPv4-адреса с длиной префикса. */
    data class Iface(val name: String, val up: Boolean, val addresses: List<Pair<IpAddress, Int>>)

    /** Что спросить у NetworkManager и что он ответил. */
    enum class Source { OK, NO_NMCLI, FAILED, UNPARSED }

    /**
     * Адреса раздачи сейчас; [seen] — что видно, для журнала: ответ
     * NetworkManager, сколько активных и общих соединений — без имён и
     * адресов (D-57).
     */
    data class Scan(val endpoints: List<ShareSpec.Endpoint>, val source: Source, val seen: String)

    fun find(): Scan {
        val active = nmcli(ACTIVE)
        if (active.code != 0) {
            val source = if (active.code == SystemCommand.NOT_FOUND) Source.NO_NMCLI else Source.FAILED
            return Scan(emptyList(), source, "nmcli=${active.code}")
        }
        val connections = parseActive(active.output) ?: return Scan(emptyList(), Source.UNPARSED, "nmcli=unparsed")
        // Соединение могло уйти между вызовами: нет ответа — не общее.
        val shared = connections.filter { (uuid, _) -> nmcli(method(uuid)).let { it.code == 0 && it.output.trim() == SHARED } }.map { it.second }.toSet()
        val endpoints = select(interfaces().orEmpty(), shared - setOfNotNull(upstream()))
        return Scan(endpoints, Source.OK, "nmcli=0 active=${connections.size} shared=${shared.size} endpoints=${endpoints.size}")
    }

    companion object {
        /** Не из PATH (T17): `nmcli` — из пакета NetworkManager. */
        val NMCLI_BINARIES: List<String> = listOf("/usr/bin/nmcli", "/bin/nmcli")

        /** Ответ о соединениях — доли секунды; дольше — NetworkManager не в порядке, и раздачи нет. */
        const val NMCLI_TIMEOUT_SECONDS: Long = 5

        /** `ipv4.method` общей сети: NetworkManager сам раздаёт адреса и пересылает трафик гостей. */
        const val SHARED: String = "shared"

        private val ACTIVE = listOf("--terse", "--fields", "UUID,DEVICE", "connection", "show", "--active")
        private val UUID = Regex("[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")

        /** Только поле `ipv4.method`; соединение — по UUID, имя могло бы совпасть с другим. */
        fun method(uuid: String): List<String> = listOf("--get-values", "ipv4.method", "connection", "show", "uuid", uuid)

        /**
         * Активные соединения (UUID, устройство) из вывода `nmcli --terse`;
         * null — строка не разобрана: лучше не раздавать, чем раздавать по
         * догадке. Соединение без устройства пропускается.
         */
        fun parseActive(output: String): List<Pair<String, String>>? = output.lines().filter { it.isNotBlank() }.map { line ->
            val fields = splitTerse(line)
            if (fields.size != 2 || !UUID.matches(fields[0])) return null
            fields[0] to fields[1]
        }.filter { (_, device) -> device.isNotEmpty() && device != "--" }

        /** Поля строки `--terse`: разделитель `:`, а `\:` и `\\` в значениях — сами знаки. */
        fun splitTerse(line: String): List<String> {
            val fields = mutableListOf<String>()
            val field = StringBuilder()
            var escaped = false
            for (c in line) {
                when {
                    escaped -> field.append(c).also { escaped = false }
                    c == '\\' -> escaped = true
                    c == ':' -> fields += field.toString().also { field.clear() }
                    else -> field.append(c)
                }
            }
            fields += field.toString()
            return fields
        }

        /**
         * Адреса входа (D-51) на интерфейсах [shared]: поднятые, их частные
         * IPv4 с местом для гостей. Порядок — по адресу: одинаковый набор —
         * одинаковый план.
         */
        fun select(interfaces: List<Iface>, shared: Set<String>): List<ShareSpec.Endpoint> = interfaces
            .filter { it.up && it.name in shared }
            .flatMap { i -> i.addresses.mapNotNull { (ip, prefix) -> ShareSpec.Endpoint.ofOrNull(ip, prefix) } }
            .distinctBy { it.address }
            .sortedBy { it.address.toString() }

        /** Интерфейсы ПК с их IPv4; не узнать — null. */
        fun systemInterfaces(): List<Iface>? = try {
            NetworkInterface.getNetworkInterfaces()?.toList().orEmpty().mapNotNull(::describe)
        } catch (e: SocketException) {
            null
        }

        /** Интерфейс, который не удалось расспросить, пропускается. */
        private fun describe(n: NetworkInterface): Iface? = try {
            Iface(
                n.name,
                n.isUp && !n.isLoopback,
                n.interfaceAddresses.mapNotNull { a ->
                    val ip = a.address as? Inet4Address ?: return@mapNotNull null
                    IpAddress.of(ip.address) to a.networkPrefixLength.toInt()
                },
            )
        } catch (e: SocketException) {
            null
        }
    }
}
