package com.dpsmpx.dppass.config

import com.dpsmpx.dppass.core.Endpoint
import com.dpsmpx.dppass.core.ProfileId
import com.dpsmpx.dppass.diagnostics.Secret
import com.dpsmpx.dppass.routing.DnsPolicy
import com.dpsmpx.dppass.routing.RoutingPolicy

/**
 * Нормализованная модель конфигурации DPpass (Config IR, D-05).
 *
 * Не знает ни одного ядра: в ней нет полей Xray или sing-box, только
 * смысл. Из неё компиляторы ядер строят свои конфигурации; интерфейс
 * пользователя работает с ней (или с документом), но никогда — с JSON
 * ядра. Все секреты — [Secret].
 */
data class ConfigIr(
    val name: String?,
    val profiles: List<ServerProfile>,
    val routing: RoutingPolicy,
    val dns: DnsPolicy,
) {
    fun profile(id: ProfileId): ServerProfile? = profiles.firstOrNull { it.id == id }
}

data class ServerProfile(
    val id: ProfileId,
    val name: String,
    val endpoint: Endpoint,
    val protocol: ProtocolSpec,
    val transport: TransportSpec,
    val security: SecuritySpec,
    val hints: CandidateHints = CandidateHints(),
)

/**
 * Подсказки для политики подключения: приоритет и в каких сетях
 * кандидат осмыслен. [reachableUnderAllowlist] — пользователь или
 * поставщик утверждает, что точка входа доступна из сети в режиме
 * белого списка (например, узел внутри страны); DPpass этого не
 * проверяет заранее и не обещает (D-13).
 */
data class CandidateHints(
    val priority: Int = 0,
    val reachableUnderAllowlist: Boolean = false,
)

enum class ProtocolKind { VLESS, TROJAN, SHADOWSOCKS, HYSTERIA2, SOCKS }

sealed interface ProtocolSpec {
    val kind: ProtocolKind

    data class Vless(val id: Secret, val flow: VlessFlow = VlessFlow.NONE) : ProtocolSpec {
        override val kind: ProtocolKind get() = ProtocolKind.VLESS
    }

    data class Trojan(val password: Secret) : ProtocolSpec {
        override val kind: ProtocolKind get() = ProtocolKind.TROJAN
    }

    data class Shadowsocks(val method: ShadowsocksMethod, val password: Secret) : ProtocolSpec {
        override val kind: ProtocolKind get() = ProtocolKind.SHADOWSOCKS
    }

    /** [congestion] — управление перегрузкой QUIC (формат 2, D-37); null — по умолчанию ядра. */
    data class Hysteria2(val password: Secret, val obfsPassword: Secret? = null, val congestion: Hysteria2Congestion? = null) : ProtocolSpec {
        override val kind: ProtocolKind get() = ProtocolKind.HYSTERIA2
    }

    /**
     * SOCKS5 с логином и паролем — только к устройству раздачи в своей сети
     * (D-55): ко входу раздачи другого DPpass (D-51). Логин, пароль и трафик
     * идут открыто по каналу раздачи, поэтому адрес — только частный IPv4.
     * В документе и подписке такого протокола нет: устройство добавляет
     * только сам пользователь (D-11).
     */
    data class Socks(val user: Secret, val password: Secret) : ProtocolSpec {
        override val kind: ProtocolKind get() = ProtocolKind.SOCKS
    }
}

/**
 * Управление перегрузкой Hysteria2 (D-37). Brutal нет: ему нужны скорости
 * канала, которых в IR нет; без них Xray и так берёт BBR.
 */
enum class Hysteria2Congestion(val wire: String) { BBR("bbr"), RENO("reno") }

enum class VlessFlow(val wire: String) { NONE("none"), VISION("vision") }

/** Только методы Shadowsocks-2022 (D-16: старые AEAD — без защиты от повтора). */
enum class ShadowsocksMethod(val wire: String) {
    BLAKE3_AES_128_GCM("2022-blake3-aes-128-gcm"),
    BLAKE3_AES_256_GCM("2022-blake3-aes-256-gcm"),
    BLAKE3_CHACHA20_POLY1305("2022-blake3-chacha20-poly1305"),
}

enum class TransportKind { TCP, WEBSOCKET, GRPC, XHTTP, HTTPUPGRADE, NATIVE }

/**
 * Класс транспорта — то, по чему политика подключения подбирает кандидата
 * под сеть: TCP-поток (TLS, REALITY, Shadowsocks поверх TCP), HTTP/CDN
 * (WebSocket, gRPC, XHTTP, HTTPUpgrade), UDP/QUIC (Hysteria2). Устройство
 * раздачи (D-55) — свой класс: до него — своя сеть, ограничения сети
 * оператора к нему не относятся, и опыт других классов на него не
 * переносится (и обратно).
 */
enum class TransportClass { TCP_STREAM, HTTP_CDN, UDP_QUIC, LOCAL_RELAY }

sealed interface TransportSpec {
    val kind: TransportKind

    data object Tcp : TransportSpec {
        override val kind: TransportKind get() = TransportKind.TCP
    }

    data class WebSocket(val path: String, val host: String?) : TransportSpec {
        override val kind: TransportKind get() = TransportKind.WEBSOCKET
    }

    data class Grpc(val serviceName: String) : TransportSpec {
        override val kind: TransportKind get() = TransportKind.GRPC
    }

    data class XHttp(val path: String, val host: String?, val mode: XHttpMode, val extra: XHttpExtra = XHttpExtra.NONE) : TransportSpec {
        override val kind: TransportKind get() = TransportKind.XHTTP
    }

    data class HttpUpgrade(val path: String, val host: String?) : TransportSpec {
        override val kind: TransportKind get() = TransportKind.HTTPUPGRADE
    }

    /** Протокол со своим транспортом (Hysteria2 — QUIC). */
    data object Native : TransportSpec {
        override val kind: TransportKind get() = TransportKind.NATIVE
    }
}

enum class XHttpMode(val wire: String) { AUTO("auto"), PACKET_UP("packet-up"), STREAM_UP("stream-up"), STREAM_ONE("stream-one") }

/**
 * Диапазон «N» или «N-M» с N ≤ M — как `Int32Range` Xray, но без молчаливой
 * перестановки концов: «M-N» с M > N — ошибка, а не «как-нибудь» (D-05).
 */
data class CountRange(val from: Int, val to: Int) {
    init {
        require(from in 0..to) { "диапазон вне 0..to" }
    }

    override fun toString(): String = if (from == to) "$from" else "$from-$to"

    companion object {
        private val TEXT = Regex("""(\d{1,9})(?:-(\d{1,9}))?""")

        /** «N» или «N-M», неотрицательные, N ≤ M; иначе null. */
        fun parse(text: String): CountRange? {
            val m = TEXT.matchEntire(text) ?: return null
            val from = m.groupValues[1].toInt()
            val to = m.groupValues[2].ifEmpty { null }?.toInt() ?: from
            return if (from <= to) CountRange(from, to) else null
        }
    }
}

/**
 * Настройки XHTTP сверх пути, имени и режима (формат 2, D-37) — то, что
 * поставщики передают в `extra`. null у поля — значение ядра по умолчанию.
 * Диапазон «0» в Xray значит то же, что отсутствие поля, поэтому в IR его
 * нет: разбор превращает «0» в null (нормализация без смены смысла).
 */
data class XHttpExtra(
    val xPaddingBytes: CountRange? = null,
    val scMaxEachPostBytes: CountRange? = null,
    val scMinPostsIntervalMs: CountRange? = null,
    val noGrpcHeader: Boolean = false,
    /** null — мультиплексирование ядра по умолчанию; заданный заменяет его целиком (как в Xray). */
    val xmux: Xmux? = null,
) {
    val isEmpty: Boolean get() = this == NONE

    companion object {
        val NONE: XHttpExtra = XHttpExtra()
    }
}

/** Мультиплексирование XHTTP (`xmux` Xray). [maxConcurrency] и [maxConnections] — не вместе. */
data class Xmux(
    val maxConcurrency: CountRange? = null,
    val maxConnections: CountRange? = null,
    val cMaxReuseTimes: CountRange? = null,
    val hMaxRequestTimes: CountRange? = null,
    val hMaxReusableSecs: CountRange? = null,
    /** Секунды; null — по умолчанию ядра, отрицательное — без keep-alive. */
    val hKeepAlivePeriod: Int? = null,
) {
    val isEmpty: Boolean get() = this == Xmux()
}

enum class SecurityKind { NONE, TLS, REALITY }

/**
 * Отпечаток TLS-клиента. Формат 1 — первые четыре; формат 2 (D-37) — все
 * готовые отпечатки Xray 26.9.30, кроме `unsafe` (TLS Go без подделки).
 * [RANDOM] — один из современных, его ядро выбирает при каждом запуске.
 */
enum class TlsFingerprint(val wire: String) {
    CHROME("chrome"),
    FIREFOX("firefox"),
    SAFARI("safari"),
    RANDOMIZED("randomized"),
    IOS("ios"),
    ANDROID("android"),
    EDGE("edge"),
    BROWSER_360("360"),
    QQ("qq"),
    RANDOM("random"),
    RANDOMIZED_NO_ALPN("randomizednoalpn"),
}

sealed interface SecuritySpec {
    val kind: SecurityKind

    data object None : SecuritySpec {
        override val kind: SecurityKind get() = SecurityKind.NONE
    }

    /**
     * Обычный TLS с проверкой сертификата. Отключить проверку
     * (`allowInsecure`) в IR нельзя — такая конфигурация отвергается
     * при разборе (D-11).
     */
    data class Tls(val serverName: String?, val alpn: List<String>, val fingerprint: TlsFingerprint?) : SecuritySpec {
        override val kind: SecurityKind get() = SecurityKind.TLS
    }

    data class Reality(
        val serverName: String,
        val publicKey: String,
        val shortId: Secret,
        val fingerprint: TlsFingerprint,
        val spiderX: String?,
    ) : SecuritySpec {
        override val kind: SecurityKind get() = SecurityKind.REALITY
    }
}

/** Класс транспорта профиля: от него зависит, в какой сети кандидат осмыслен. */
val ServerProfile.transportClass: TransportClass
    get() = when {
        protocol.kind == ProtocolKind.SOCKS -> TransportClass.LOCAL_RELAY
        protocol.kind == ProtocolKind.HYSTERIA2 -> TransportClass.UDP_QUIC
        transport.kind == TransportKind.TCP -> TransportClass.TCP_STREAM
        else -> TransportClass.HTTP_CDN
    }
