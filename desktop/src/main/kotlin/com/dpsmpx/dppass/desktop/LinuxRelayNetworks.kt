package com.dpsmpx.dppass.desktop

import com.dpsmpx.dppass.connection.Pairing
import com.dpsmpx.dppass.connection.RelayDevice
import com.dpsmpx.dppass.connection.Socks5Login
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
 * Где искать устройство раздачи с ПК (D-85, к D-55): на шлюзе сети, через
 * которую ПК к нему подключён, — точки доступа Wi-Fi, USB- или
 * Bluetooth-модема телефона. Ничего не объявляется и не рассылается: ПК
 * спрашивает шлюзы своих сетей по протоколу входа раздачи — SOCKS5 с
 * паролем (RFC 1929), — и ответит только вход, который знает этот логин и
 * пароль.
 *
 * Сокеты — мимо туннеля ([sockets]: метка, как у сокетов ядра, D-74):
 * адрес устройства частный, и при `bypass_lan = false` поиск ушёл бы в
 * туннель. Привязывать к сети, как на Android, не нужно: у таблицы `main`
 * есть маршрут к подсети каждого интерфейса.
 */
class LinuxRelayNetworks(
    /** Сокет мимо туннеля, ещё не соединённый. */
    private val sockets: () -> Socket,
    private val route: () -> String? = { readOrNull(File("/proc/net/route")) },
    private val medium: (String) -> Medium = ::systemMedium,
    private val interfaces: () -> List<LinuxShareInterfaces.Iface>? = LinuxShareInterfaces::systemInterfaces,
) {
    enum class Medium { WIFI, USB, BLUETOOTH, WIRED }

    /** Шлюз IPv4 сети ПК в частных адресах — возможное устройство раздачи. */
    data class Gateway(val iface: String, val medium: Medium, val address: IpAddress)

    /** Где ответило устройство: по какой сети и по какому адресу. */
    data class Target(val medium: Medium, val address: IpAddress)

    /** Шлюзы маршрутов по умолчанию таблицы `main` — снимок на сейчас; не прочитать — пусто. */
    fun gateways(): List<Gateway> = parseGateways(route().orEmpty()).map { (iface, gw) -> Gateway(iface, medium(iface), gw) }

    /**
     * Найти устройство: по его явному адресу — если он в подсети одного из
     * интерфейсов ПК; без адреса — среди шлюзов. Первый вход, принявший логин
     * и пароль, — ответ. Блокирует поток: по короткому соединению на кандидата.
     */
    fun locate(device: RelayDevice): Outcome<Target> {
        val candidates = device.address?.let { at ->
            interfaces().orEmpty().filter { it.up }.flatMap { i ->
                i.addresses.filter { (own, prefix) -> at in Cidr.of(own, prefix) }.map { Target(medium(i.name), at) }
            }.distinct()
        } ?: gateways().map { Target(it.medium, it.address) }.distinct()
        if (candidates.isEmpty()) {
            return Outcome.failure(
                DiagCode.RELAY_NOT_FOUND,
                "ПК не подключён к устройству раздачи: подключите его к точке доступа Wi-Fi, USB- или Bluetooth-модему того телефона",
            )
        }
        var rejected = false
        for (c in candidates) {
            when (check(c.address, device)) {
                Socks5Login.Result.ACCEPTED -> return Outcome.Success(c)
                Socks5Login.Result.REJECTED -> rejected = true
                Socks5Login.Result.NOT_SOCKS, null -> Unit
            }
        }
        return if (rejected) {
            Outcome.failure(
                DiagCode.AUTHENTICATION_FAILED,
                "устройство раздачи не приняло логин и пароль: на нём их сменили («Новые логин, пароль и порт») — добавьте устройство заново",
            )
        } else {
            Outcome.failure(
                DiagCode.RELAY_NOT_FOUND,
                "устройство раздачи не ответило: на нём выключена «Раздача туннеля» или DPpass не подключён, либо сменился порт",
            )
        }
    }

    /** Вход раздачи [device] по [address]; null — не ответил вовсе. */
    fun check(address: IpAddress, device: RelayDevice): Socks5Login.Result? = try {
        connect(address, device.port).use { s ->
            s.soTimeout = READ_TIMEOUT_MILLIS
            Socks5Login.check(s.getInputStream(), s.getOutputStream(), device.user, device.password)
        }
    } catch (e: IOException) {
        null
    }

    /**
     * Сопряжение (D-56, гость): шлюз сети ПК, на котором ждут сопряжения, —
     * первое удачное соединение. null — никто не ждёт.
     */
    fun pairingHost(): Socket? {
        for (g in gateways().distinctBy { it.address }) {
            try {
                return connect(g.address, Pairing.PORT).apply { soTimeout = Pairing.WINDOW_MILLIS.toInt() }
            } catch (e: IOException) {
                // Не ждёт — следующий шлюз.
            }
        }
        return null
    }

    private fun connect(address: IpAddress, port: Int): Socket {
        val s = sockets()
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
        fun systemMedium(iface: String): Medium = medium(
            iface,
            wireless = File("/sys/class/net/$iface/wireless").isDirectory,
            bus = runCatching { File("/sys/class/net/$iface/device/subsystem").canonicalFile.name }.getOrNull(),
        )

        fun medium(iface: String, wireless: Boolean, bus: String?): Medium = when {
            wireless -> Medium.WIFI
            iface.startsWith("bnep") -> Medium.BLUETOOTH
            bus == "usb" -> Medium.USB
            else -> Medium.WIRED
        }

        private fun readOrNull(f: File): String? = try {
            f.readText()
        } catch (e: IOException) {
            null
        }
    }
}
