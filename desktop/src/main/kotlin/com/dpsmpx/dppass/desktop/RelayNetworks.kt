package com.dpsmpx.dppass.desktop

import com.dpsmpx.dppass.connection.Pairing
import com.dpsmpx.dppass.connection.RelayDevice
import com.dpsmpx.dppass.core.Cidr
import com.dpsmpx.dppass.core.IpAddress
import com.dpsmpx.dppass.diagnostics.DiagCode
import com.dpsmpx.dppass.diagnostics.Outcome
import java.io.File
import java.io.IOException
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket

/**
 * Возможный адрес устройства раздачи. Поиск проверяет только доступность TCP-порта,
 * без логина, пароля или ключа. Ответ шлюза не удостоверяет устройство (D-110).
 * Передача данных и проверка ключа выполняются SS2022 при подключении.
 */
class RelayNetworks(
    /** Сокет мимо туннеля, ещё не соединённый, — к интерфейсу с этим номером (Linux номер не смотрит: метка). */
    private val sockets: (Int) -> Socket,
    /** Шлюзы маршрутов по умолчанию в частных адресах — снимок на сейчас; не узнать — пусто. */
    private val gatewaysOf: () -> List<Gateway>,
    /** Интерфейсы ПК с их IPv4; не узнать — null. */
    private val interfaces: () -> List<Iface>?,
) {
    /** Вид сети — подпись в окне; числа на Windows — договор с мостом (`tools/xray/bridge/relay_windows.go`). */
    enum class Medium { WIRED, WIFI, USB, BLUETOOTH }

    /** Шлюз IPv4 сети ПК в частных адресах — возможное устройство раздачи; [index] — номер интерфейса (Windows). */
    data class Gateway(val iface: String, val medium: Medium, val address: IpAddress, val index: Int = 0)

    /** Интерфейс ПК: поднят ли и его IPv4 с длиной префикса. */
    data class Iface(val name: String, val medium: Medium, val up: Boolean, val addresses: List<Pair<IpAddress, Int>>, val index: Int = 0)

    /**
     * Где ответило устройство: по какой сети и по какому адресу; [iface] и
     * [index] — интерфейс этой сети: к нему на Windows привязываются сокеты
     * ядра (D-102).
     */
    data class Target(val medium: Medium, val address: IpAddress, val iface: String = "", val index: Int = 0)

    fun gateways(): List<Gateway> = gatewaysOf()

    /**
     * Найти устройство: по его явному адресу — если он в подсети одного из
     * интерфейсов ПК; без адреса — среди шлюзов. Первый вход, принявший логин
     * и пароль, — ответ. Блокирует поток: по короткому соединению на кандидата.
     */
    fun locate(device: RelayDevice): Outcome<Target> {
        val candidates = device.address?.let { at ->
            interfaces().orEmpty().filter { it.up }.flatMap { i ->
                i.addresses.filter { (own, prefix) -> at in Cidr.of(own, prefix) }.map { Target(i.medium, at, i.name, i.index) }
            }.distinct()
        } ?: gateways().map { Target(it.medium, it.address, it.iface, it.index) }.distinct()
        if (candidates.isEmpty()) {
            return Outcome.failure(
                DiagCode.RELAY_NOT_FOUND,
                "ПК не подключён к устройству раздачи: подключите его к точке доступа Wi-Fi, USB- или Bluetooth-модему того телефона",
            )
        }
        // Только доступность порта. Личность подтвердит зашифрованное соединение SS2022,
        // а TCP accept чужого шлюза не разрешает передавать ему открытые учётные данные.
        for (c in candidates) {
            if (check(c, device)) return Outcome.Success(c)
        }
        return Outcome.failure(DiagCode.RELAY_NOT_FOUND, "порт устройства раздачи недоступен: проверьте подключение и выполните новое сопряжение")
    }

    /** Вход раздачи [device] в [target]; null — не ответил вовсе. */
    fun check(target: Target, device: RelayDevice): Boolean = try {
        connect(target.address, device.port, target.index).use { s ->
            true // Ни одного байта аутентификации возможному шлюзу.
        }
    } catch (e: IOException) {
        false
    }

    /**
     * Сопряжение (D-56, гость): шлюз сети ПК, на котором ждут сопряжения, —
     * первое удачное соединение. null — никто не ждёт.
     */
    fun pairingHost(): Socket? {
        for (g in gateways().distinctBy { it.address }) {
            try {
                return connect(g.address, Pairing.PORT, g.index).apply { soTimeout = Pairing.WINDOW_MILLIS.toInt() }
            } catch (e: IOException) {
                // Не ждёт — следующий шлюз.
            }
        }
        return null
    }

    private fun connect(address: IpAddress, port: Int, index: Int): Socket {
        val s = sockets(index)
        try {
            // Адрес из байтов — без DNS: getByAddress имён не резолвит.
            s.connect(InetSocketAddress(InetAddress.getByAddress(address.toBytes()), port), CONNECT_TIMEOUT_MILLIS)
            return s
        } catch (e: IOException) {
            runCatching { s.close() }
            throw e
        }
    }

    companion object {
        const val CONNECT_TIMEOUT_MILLIS: Int = 1_500
        const val READ_TIMEOUT_MILLIS: Int = 1_500
    }
}

/**
 * Сети ПК на Linux (D-85): шлюзы — из `/proc/net/route` (таблица `main`),
 * интерфейсы — из JDK. Сокеты — с меткой, как у сокетов ядра (D-74):
 * привязывать к сети, как на Android, не нужно — у таблицы `main` есть
 * маршрут к подсети каждого интерфейса.
 */
object LinuxRelayNetworks {
    fun create(
        /** Сокет мимо туннеля, ещё не соединённый. */
        sockets: () -> Socket,
        route: () -> String? = { readOrNull(File("/proc/net/route")) },
        medium: (String) -> RelayNetworks.Medium = ::systemMedium,
        interfaces: () -> List<LinuxShareInterfaces.Iface>? = LinuxShareInterfaces::systemInterfaces,
    ): RelayNetworks = RelayNetworks(
        { sockets() },
        { parseGateways(route().orEmpty()).map { (iface, gw) -> RelayNetworks.Gateway(iface, medium(iface), gw) } },
        { interfaces()?.map { RelayNetworks.Iface(it.name, medium(it.name), it.up, it.addresses) } },
    )

    /**
     * Шлюзы маршрутов по умолчанию из текста `/proc/net/route`: интерфейс и
     * частный IPv4 шлюза (поле — 32 бита в порядке байтов ядра, на x86 и
     * arm — младший первым). Без шлюза и публичные — не устройство раздачи.
     */
    fun parseGateways(route: String): List<Pair<String, IpAddress>> = route.lines().drop(1)
        .map { it.trim().split(Regex("\\s+")) }
        .filter { f -> f.size >= 8 && f[1] == "00000000" && f[7] == "00000000" }
        .mapNotNull { f -> gateway(f[2])?.let { f[0] to it } }
        .filter { (_, gw) -> Cidr.isPrivateV4(gw) }
        .distinct()

    private fun gateway(hex: String): IpAddress? {
        val v = hex.toLongOrNull(16)?.takeIf { hex.length == 8 && it != 0L } ?: return null
        return IpAddress.of(ByteArray(4) { i -> (v shr (8 * i)).toByte() })
    }

    /** Вид сети по интерфейсу: беспроводной — Wi-Fi, `bnep*` — Bluetooth (PAN), устройство на шине USB — USB-модем. */
    fun systemMedium(iface: String): RelayNetworks.Medium = medium(
        iface,
        wireless = File("/sys/class/net/$iface/wireless").isDirectory,
        bus = runCatching { File("/sys/class/net/$iface/device/subsystem").canonicalFile.name }.getOrNull(),
    )

    fun medium(iface: String, wireless: Boolean, bus: String?): RelayNetworks.Medium = when {
        wireless -> RelayNetworks.Medium.WIFI
        iface.startsWith("bnep") -> RelayNetworks.Medium.BLUETOOTH
        bus == "usb" -> RelayNetworks.Medium.USB
        else -> RelayNetworks.Medium.WIRED
    }

    private fun readOrNull(f: File): String? = try {
        f.readText()
    } catch (e: IOException) {
        null
    }
}
