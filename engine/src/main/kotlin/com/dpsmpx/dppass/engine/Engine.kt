package com.dpsmpx.dppass.engine

import com.dpsmpx.dppass.config.ConfigIr
import com.dpsmpx.dppass.config.ProtocolKind
import com.dpsmpx.dppass.config.SecurityKind
import com.dpsmpx.dppass.config.TransportKind
import com.dpsmpx.dppass.config.VlessFlow
import com.dpsmpx.dppass.core.Cidr
import com.dpsmpx.dppass.core.IpAddress
import com.dpsmpx.dppass.core.ProfileId
import com.dpsmpx.dppass.diagnostics.Outcome
import com.dpsmpx.dppass.diagnostics.Secret
import com.dpsmpx.dppass.routing.RouteDecision
import com.dpsmpx.dppass.routing.RouteEvaluator
import com.dpsmpx.dppass.routing.RouteQuery
import com.dpsmpx.dppass.routing.RoutingPolicy

/** Возможности, которые бывают не у каждого ядра. */
enum class EngineFeature {
    /** Ядро само знает приложение-владельца соединения (правила с apps внутри ядра). */
    APP_RULES_IN_ENGINE,

    /** IP-правила к домену после резолва (DomainResolution.IF_NO_DOMAIN_MATCH). */
    DOMAIN_RESOLUTION_IF_NO_MATCH,
    DNS_DOH,
    DNS_DOT,
    DNS_RULES,
    GEOSITE,
    GEOIP,

    /** Ядро принимает fd TUN от платформы. */
    TUN_FD,

    /** Ядро различает сеть устройства (условие network в правилах). */
    NETWORK_CONDITION,
}

/**
 * Матрица возможностей одного ядра одной версии (D-04, D-18).
 *
 * Смена версии ядра — это смена матрицы: разница матриц
 * (`capabilityDiff`) — обязательная часть обзора обновления.
 */
data class EngineCapabilities(
    val backendId: String,
    val backendVersion: String,
    val protocols: Set<ProtocolKind>,
    val transports: Set<TransportKind>,
    val securities: Set<SecurityKind>,
    val flows: Set<VlessFlow>,
    val features: Set<EngineFeature>,
)

data class CapabilityDiff(val added: Set<String>, val removed: Set<String>) {
    val isEmpty: Boolean get() = added.isEmpty() && removed.isEmpty()
}

fun capabilityDiff(old: EngineCapabilities, new: EngineCapabilities): CapabilityDiff {
    fun flat(c: EngineCapabilities): Set<String> =
        c.protocols.map { "protocol:$it" }.toSet() + c.transports.map { "transport:$it" } +
            c.securities.map { "security:$it" } + c.flows.map { "flow:$it" } + c.features.map { "feature:$it" }
    val a = flat(old)
    val b = flat(new)
    return CapabilityDiff(added = b - a, removed = a - b)
}

/**
 * Скомпилированная конфигурация конкретного ядра. Содержимое — с
 * секретами, поэтому `toString()` его не показывает; контрольная сумма
 * — для журнала и истории активаций.
 */
class CompiledConfig(
    val backendId: String,
    val backendVersion: String,
    val profileId: ProfileId,
    private val payload: String,
    val checksum: String,
) {
    /** Только для передачи ядру и для тестов компилятора. */
    fun payloadForEngine(): String = payload

    override fun toString(): String = "CompiledConfig($backendId $backendVersion, profile=$profileId, sha256=${checksum.take(12)})"
}

/**
 * Что именно компилировать: какой профиль активен, есть ли TUN и
 * раздаётся ли туннель другим устройствам ([share], D-51).
 */
data class CompilePlan(val profileId: ProfileId, val withTun: Boolean, val share: ShareSpec? = null)

/**
 * Раздача туннеля другим устройствам (D-51): вход прокси с логином и
 * паролем — только на адресах [endpoints] (частные IPv4 интерфейсов
 * раздачи: точка доступа, USB- и Bluetooth-модем), на порту [port].
 * Пускать — только клиентов из подсетей раздачи и не с адресов самого
 * телефона: так прокси не достаётся приложениям телефона.
 *
 * [guests] — свои входы сопряжённых устройств (D-56): у каждого — свой
 * логин, чтобы доверие можно было отозвать у одного. Логины не
 * повторяются: ядро держит входы по логину, и повтор молча заменил бы
 * один пароль другим (D-05).
 */
data class ShareSpec(
    val endpoints: List<Endpoint>,
    val port: Int,
    val user: Secret,
    val password: Secret,
    val guests: List<Account> = emptyList(),
) {
    init {
        require(endpoints.isNotEmpty()) { "раздача без адресов" }
        require(endpoints.map { it.address }.distinct().size == endpoints.size) { "адрес раздачи повторяется" }
        require(port in MIN_PORT..MAX_PORT) { "порт раздачи вне $MIN_PORT..$MAX_PORT" }
        require((listOf(user) + guests.map { it.user }).distinct().size == guests.size + 1) { "логин входа раздачи повторяется" }
    }

    /** Все входы: основной и сопряжённых устройств. */
    val accounts: List<Account> get() = listOf(Account(user, password)) + guests

    data class Account(val user: Secret, val password: Secret)

    /**
     * Адрес телефона на интерфейсе раздачи и длина префикса его подсети:
     * клиенты раздачи приходят из этой подсети. Подсеть — целиком внутри
     * частных адресов (RFC 1918), иначе «клиентом раздачи» оказался бы
     * кто угодно из интернета.
     */
    data class Endpoint(val address: IpAddress, val prefix: Int) {
        init {
            require(isPrivateV4(address)) { "раздача только на частных IPv4-адресах" }
            require(prefix <= MAX_PREFIX && PRIVATE_V4.any { subnet.isWithin(it) }) { "подсеть раздачи не внутри частных адресов" }
        }

        val subnet: Cidr get() = Cidr.of(address, prefix)

        override fun toString(): String = "$address/$prefix"

        companion object {
            /** Адрес интерфейса, годный для раздачи (те же условия, что у конструктора), — или null. */
            fun ofOrNull(address: IpAddress, prefix: Int): Endpoint? {
                if (!isPrivateV4(address) || prefix !in 0..MAX_PREFIX) return null
                return if (PRIVATE_V4.any { Cidr.of(address, prefix).isWithin(it) }) Endpoint(address, prefix) else null
            }
        }
    }

    companion object {
        const val MIN_PORT: Int = 1024
        const val MAX_PORT: Int = 65535

        /** Длиннее /30 — в подсети нет места для клиентов. */
        const val MAX_PREFIX: Int = 30

        /** RFC 1918: 10/8, 172.16/12, 192.168/16 — адреса, которые не видны из интернета. */
        val PRIVATE_V4: List<Cidr> = Cidr.PRIVATE_V4

        fun isPrivateV4(ip: IpAddress): Boolean = Cidr.isPrivateV4(ip)
    }
}

/**
 * IR → конфигурация ядра. Обязан сохранить смысл IR или отказать с
 * диагностикой; приблизительная замена допустима только как явный
 * SEMANTIC_FALLBACK в находках (D-05).
 */
interface BackendCompiler {
    val capabilities: EngineCapabilities

    fun compile(ir: ConfigIr, plan: CompilePlan): Outcome<CompiledConfig>
}

/**
 * Держит собственный сокет ядра вне TUN — на Android `VpnService.protect`
 * (D-25). Ложь — сокет не защищён; ядро тогда его не использует.
 * Вызывается из потоков ядра, параллельно.
 */
fun interface SocketProtector {
    fun protect(socketFd: Int): Boolean
}

/**
 * Вход TUN для ядра: fd от платформы, MTU и защитник сокетов ядра от
 * петли через этот же TUN. Домен про fd больше ничего не знает; fd
 * принадлежит платформе и закрывается ею после остановки ядра.
 */
data class TunInput(val fd: Int, val mtu: Int, val protector: SocketProtector)

enum class EngineState { STOPPED, STARTING, RUNNING, STOPPING, FAILED }

data class TrafficStats(val uplinkBytes: Long, val downlinkBytes: Long)

/** Запущенное ядро. */
interface EngineSession {
    val compiled: CompiledConfig

    fun state(): EngineState

    fun stats(): TrafficStats

    suspend fun stop()
}

/**
 * Граница ядра (D-04). Реализации: Xray (`xray.XrayProxyEngine`, D-25) и
 * фиктивная [mock] — второй бэкенд в тестах. Домен не знает, какая из
 * них работает.
 */
interface ProxyEngine {
    val capabilities: EngineCapabilities

    /** Проверка конфигурации самим ядром без запуска (у Xray — `-test`). */
    suspend fun validate(config: CompiledConfig): Outcome<Unit>

    suspend fun start(config: CompiledConfig, tun: TunInput?): Outcome<EngineSession>

    /**
     * Объяснение решения маршрутизации (D-09): [RouteEvaluator] на
     * геоданных этого ядра (D-27), чтобы объяснение не расходилось с тем,
     * что ядро делает с трафиком. Отказ — геоданные не ответили: решение с
     * geosite или geoip тогда не объясняется, а не подменяется ответом «не
     * сработало» (D-05). Блокирует поток: ядро может читать файлы набора.
     *
     * По умолчанию геоданных у ядра нет ([com.dpsmpx.dppass.routing.GeoResolver.None]) —
     * так у фиктивного ядра.
     */
    fun explain(policy: RoutingPolicy, query: RouteQuery): Outcome<RouteDecision> =
        Outcome.Success(RouteEvaluator(policy).decide(query))
}
