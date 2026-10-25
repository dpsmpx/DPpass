package com.dpsmpx.dppass.engine

import com.dpsmpx.dppass.config.ConfigIr
import com.dpsmpx.dppass.config.ProtocolKind
import com.dpsmpx.dppass.config.SecurityKind
import com.dpsmpx.dppass.config.TransportKind
import com.dpsmpx.dppass.config.VlessFlow
import com.dpsmpx.dppass.core.Cidr
import com.dpsmpx.dppass.core.IpAddress
import com.dpsmpx.dppass.core.ProfileId
import com.dpsmpx.dppass.diagnostics.DiagCode
import com.dpsmpx.dppass.diagnostics.Diagnostic
import com.dpsmpx.dppass.diagnostics.Outcome
import com.dpsmpx.dppass.diagnostics.Secret
import com.dpsmpx.dppass.routing.DnsPolicy
import com.dpsmpx.dppass.routing.RouteDecision
import com.dpsmpx.dppass.routing.RouteEvaluator
import com.dpsmpx.dppass.routing.RouteQuery
import com.dpsmpx.dppass.routing.RoutingPolicy
import com.dpsmpx.dppass.routing.SplitSites

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
 * Что именно компилировать: какой профиль активен, есть ли TUN,
 * раздаётся ли туннель другим устройствам ([share], D-51), разбивать ли
 * TLS ClientHello к серверу на части ([splitClientHello], D-68: выбор
 * пользователя, по умолчанию — нет), какие сайты вести напрямую с
 * разбиением ([splitSites], D-72: список пользователя, по умолчанию пуст)
 * и есть ли локальный прокси для подключения без VPN ([local], D-95:
 * только без TUN).
 */
data class CompilePlan(
    val profileId: ProfileId,
    val withTun: Boolean,
    val share: ShareSpec? = null,
    val splitClientHello: Boolean = false,
    val splitSites: SplitSites = SplitSites.NONE,
    val local: LocalProxySpec? = null,
)

/**
 * Подключение без VPN (D-95): вход SOCKS5 (он же HTTP-прокси) с логином и
 * паролем — только на `127.0.0.1` и только без TUN. Приложения устройства,
 * которым пользователь указал адрес и пароль, ходят через него; остальные —
 * мимо DPpass, как без него. Вход без пароля был бы доступен любому
 * приложению устройства (T11).
 */
data class LocalProxySpec(val port: Int, val user: Secret, val password: Secret) {
    init {
        require(port in ShareSpec.MIN_PORT..ShareSpec.MAX_PORT) { "порт локального прокси вне ${ShareSpec.MIN_PORT}..${ShareSpec.MAX_PORT}" }
        require(user.reveal().isNotEmpty() && password.reveal().isNotEmpty()) { "локальный прокси — только с логином и паролем (T11)" }
    }

    companion object {
        /** Адрес входа: только loopback IPv4 — с других устройств и из сети его не видно. */
        const val ADDRESS: String = "127.0.0.1"
    }
}

/**
 * Без сервера (D-73): только прямые выходы. Сайты [splitSites] — с
 * разбиением начала TLS, UDP 443 к ним закрыт; остальное — напрямую или,
 * если [splitRest], тоже с разбиением. Имена — по [dns] (DoH напрямую или
 * системный резолвер); у сервера DNS нет маршрута через туннель.
 */
data class ServerlessPlan(
    val dns: DnsPolicy,
    val splitSites: SplitSites,
    val splitRest: Boolean,
    val withTun: Boolean = true,
) {
    companion object {
        /** Сеанс без сервера в `CompiledConfig.profileId`: не профиль документа — в id профиля нет двоеточий. */
        val PROFILE_ID: ProfileId = ProfileId("dppass:serverless")
    }
}

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

    /**
     * Список «Напрямую с разбиением» (D-72) — против того, что знает ядро
     * (коды geosite набора геоданных, D-27): до сохранения в настройках, а
     * не отказом подключения. Без ядра — ничего не проверяется.
     */
    fun checkSplitSites(sites: SplitSites): List<Diagnostic> = emptyList()

    /**
     * Коды geosite и geoip (свои списки, D-93) — против набора геоданных
     * ядра (D-27): запись с кодом, которого нет, — до сохранения, а не
     * отказом подключения. Без ядра — ничего не проверяется.
     */
    fun checkGeoCodes(geoSites: List<String>, geoIps: List<String>, path: String): List<Diagnostic> = emptyList()

    fun compile(ir: ConfigIr, plan: CompilePlan): Outcome<CompiledConfig>

    /** Конфигурация без сервера (D-73); ядро, которое так не умеет, — отказ, а не подмена (D-05). */
    fun compileServerless(plan: ServerlessPlan): Outcome<CompiledConfig> =
        Outcome.failure(DiagCode.CAPABILITY_FEATURE_UNSUPPORTED, "${capabilities.backendId}: режима без сервера нет")
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
