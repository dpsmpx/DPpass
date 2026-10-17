package com.dpsmpx.dppass.app

import android.content.Context
import android.content.IntentFilter
import android.net.ConnectivityManager
import android.os.Build
import com.dpsmpx.dppass.core.IpAddress
import com.dpsmpx.dppass.engine.ShareSpec
import java.net.Inet4Address
import java.net.NetworkInterface
import java.net.SocketException

/**
 * Интерфейсы раздачи (D-51, D-57): точка доступа, USB- и Bluetooth-модем.
 *
 * Сначала — по сведениям самой системы: её липкая рассылка о состоянии
 * раздачи называет интерфейсы, которые сейчас раздают
 * (`docs/research/ANDROID_NETWORK_MODEL.md`, §9). Названным системой
 * интерфейсам признаки ниже не нужны: на Android 15 раздача может и
 * значиться сетью, и быть без широковещательного адреса.
 *
 * Сведений нет — по признакам: поднят, широковещательный (не
 * точка-точка, как TUN и часто мобильная связь), частный IPv4 с местом для
 * клиентов — и это **не** сеть `ConnectivityManager`: Wi-Fi-клиент,
 * мобильная связь и VPN — сети «вверх по течению», раздача — «вниз». По
 * имени не узнаётся: у производителей имена разные.
 *
 * Ошибка в сторону «не раздавать»: не удалось узнать сети устройства —
 * интерфейсов раздачи нет, иначе вход мог бы встать на адрес Wi-Fi-клиента.
 */
object TetherInterfaces {
    /** Липкая рассылка системы о раздаче (AOSP `TetheringManager`): действие и список раздающих интерфейсов. */
    private const val ACTION_TETHER_STATE_CHANGED = "android.net.conn.TETHER_STATE_CHANGED"
    private const val EXTRA_ACTIVE_TETHER = "tetherArray"

    /** Что известно об интерфейсе; без Android — для проверки выбора на хосте. */
    data class Iface(
        val name: String,
        val up: Boolean,
        val loopback: Boolean,
        val pointToPoint: Boolean,
        val addresses: List<Address>,
    )

    /** IPv4-адрес интерфейса: длина префикса и есть ли широковещательный адрес. */
    data class Address(val ip: IpAddress, val prefix: Int, val broadcast: Boolean)

    /** Интерфейсы раздачи сейчас; не удалось узнать — пусто. */
    fun find(context: Context): List<ShareSpec.Endpoint> {
        val all = interfaces() ?: return emptyList()
        val named = systemTethered(context)
        if (!named.isNullOrEmpty()) return selectNamed(all, named)
        val upstream = upstream(context) ?: return emptyList()
        return select(all, upstream)
    }

    /**
     * Что видно, когда раздача не найдена (D-57) — для журнала: что говорит
     * система и каждый интерфейс с IPv4 — признаки и длина префикса, без
     * адресов.
     */
    fun snapshot(context: Context): String {
        val named = systemTethered(context)
        val upstream = upstream(context)
        val ifaces = interfaces().orEmpty().filter { it.addresses.isNotEmpty() || named?.contains(it.name) == true }.joinToString(";") { i ->
            val flags = listOfNotNull(
                "up".takeIf { i.up },
                "p2p".takeIf { i.pointToPoint },
                "net".takeIf { upstream?.contains(i.name) == true },
                "sys".takeIf { named?.contains(i.name) == true },
            ) + i.addresses.map { a -> "/${a.prefix}" + (if (a.broadcast) "b" else "") + (if (ShareSpec.isPrivateV4(a.ip)) "p" else "") }
            "${i.name}(${flags.joinToString(",")})"
        }
        return "system=${named?.sorted()?.joinToString(",") ?: "?"} ifaces=$ifaces"
    }

    /**
     * Интерфейсы, которые система назвала раздачей (D-57): поднятые, их
     * частные IPv4 с местом для клиентов. Сетью ли они значатся и есть ли
     * широковещание — не важно: система сама сказала, что это раздача.
     */
    fun selectNamed(interfaces: List<Iface>, named: Set<String>): List<ShareSpec.Endpoint> = interfaces
        .filter { it.up && !it.loopback && it.name in named }
        .flatMap { i -> i.addresses.mapNotNull { ShareSpec.Endpoint.ofOrNull(it.ip, it.prefix) } }
        .distinctBy { it.address }
        .sortedBy { it.address.toString() }

    /**
     * Раздающие интерфейсы по липкой рассылке системы (D-57); null — сведений
     * нет. Приёмник не регистрируется: только последнее состояние.
     */
    private fun systemTethered(context: Context): Set<String>? {
        val filter = IntentFilter(ACTION_TETHER_STATE_CHANGED)
        val sticky = try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                context.registerReceiver(null, filter, Context.RECEIVER_EXPORTED)
            } else {
                context.registerReceiver(null, filter)
            }
        } catch (e: RuntimeException) {
            null
        } ?: return null
        return sticky.getStringArrayListExtra(EXTRA_ACTIVE_TETHER)?.toSet()
    }

    private fun interfaces(): List<Iface>? = try {
        NetworkInterface.getNetworkInterfaces()?.toList().orEmpty().mapNotNull(::describe)
    } catch (e: SocketException) {
        null
    }

    /**
     * Выбор (D-51): интерфейсы не из [upstream], поднятые, не loopback и не
     * точка-точка; их частные IPv4-адреса с широковещанием и подсетью для
     * клиентов. Порядок — по адресу: одинаковый набор — одинаковый план.
     */
    fun select(interfaces: List<Iface>, upstream: Set<String>): List<ShareSpec.Endpoint> = interfaces
        .filter { it.up && !it.loopback && !it.pointToPoint && it.name !in upstream }
        .flatMap { i -> i.addresses.filter { it.broadcast }.mapNotNull { ShareSpec.Endpoint.ofOrNull(it.ip, it.prefix) } }
        .distinctBy { it.address }
        .sortedBy { it.address.toString() }

    /**
     * Переподключаться ли (D-51), когда опрос дал [wanted], а туннель
     * раздаёт на [current]. Пропал интерфейс — сразу. Новый — только если
     * виден два опроса подряд ([previous] — прошлый опрос): сеть
     * Wi-Fi-клиента в первые секунды может ещё не значиться в
     * `ConnectivityManager` и на миг выглядеть интерфейсом раздачи.
     */
    fun shouldReconnect(current: List<ShareSpec.Endpoint>, wanted: List<ShareSpec.Endpoint>, previous: List<ShareSpec.Endpoint>?): Boolean {
        if (wanted.toSet() == current.toSet()) return false
        return current.containsAll(wanted) || wanted.toSet() == previous?.toSet()
    }

    /**
     * Адреса для подключения (D-51) — из двух снимков подряд: только те, что
     * есть в обоих. По той же причине, что в [shouldReconnect]: сеть
     * Wi-Fi-клиента на миг может выглядеть интерфейсом раздачи, и вход
     * встал бы на её адрес.
     */
    fun confirmed(first: List<ShareSpec.Endpoint>, second: List<ShareSpec.Endpoint>): List<ShareSpec.Endpoint> =
        first.filter { it in second }

    /** Имена интерфейсов сетей устройства; null — узнать не удалось. */
    private fun upstream(context: Context): Set<String>? {
        val cm = context.getSystemService(ConnectivityManager::class.java) ?: return null
        return try {
            // Замена — колбэки сетей; здесь нужен снимок раз в несколько секунд, а не
            // ещё одна регистрация колбэка (у процесса их не больше 100).
            @Suppress("DEPRECATION")
            val networks = cm.allNetworks
            networks.mapNotNull { cm.getLinkProperties(it)?.interfaceName }.toSet()
        } catch (e: RuntimeException) {
            null
        }
    }

    /** Интерфейс, который не удалось расспросить, пропускается. */
    private fun describe(n: NetworkInterface): Iface? = try {
        Iface(
            name = n.name,
            up = n.isUp,
            loopback = n.isLoopback,
            pointToPoint = n.isPointToPoint,
            addresses = n.interfaceAddresses.mapNotNull { a ->
                val ip = a.address as? Inet4Address ?: return@mapNotNull null
                Address(IpAddress.of(ip.address), a.networkPrefixLength.toInt(), a.broadcast != null)
            },
        )
    } catch (e: SocketException) {
        null
    }
}
