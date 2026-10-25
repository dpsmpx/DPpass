package com.dpsmpx.dppass.engine.xray

import com.dpsmpx.dppass.config.ProtocolKind
import com.dpsmpx.dppass.config.SecurityKind
import com.dpsmpx.dppass.config.TransportKind
import com.dpsmpx.dppass.config.VlessFlow
import com.dpsmpx.dppass.engine.EngineCapabilities
import com.dpsmpx.dppass.engine.EngineFeature
import com.dpsmpx.dppass.routing.RouteAction

/**
 * Xray-core — первое реальное ядро (D-03), версия закреплена (D-18, D-24):
 * `gradle/libs.versions.toml` (`xray`), исходники — `tools/xray/go.mod`.
 *
 * Матрица — что из IR v1 (D-16) эта версия выражает без потери смысла.
 * Каждая строка подтверждена исходниками 26.9.30 и проверяется самим
 * ядром на корпусе (шаг hostcheck «Xray», `docs/TESTING.md`, «Эталоны Xray»).
 * Нет:
 * - [EngineFeature.DNS_DOT] — DNS-over-TLS в Xray нет вовсе (виды адресов
 *   сервера — `app/dns/nameserver.go`, `NewServer`);
 * - [EngineFeature.APP_RULES_IN_ENGINE] — правило `process` сопоставляет
 *   процессы ОС хоста, а на Android ядро получает пакеты из TUN без
 *   владельца; приложения — уровень VpnService (`AppLowering`);
 * - [EngineFeature.NETWORK_CONDITION] — вида физической сети ядро не знает.
 */
object XrayBackend {
    const val ID: String = "xray"
    const val VERSION: String = "26.9.30"

    val CAPABILITIES: EngineCapabilities = EngineCapabilities(
        backendId = ID,
        backendVersion = VERSION,
        protocols = setOf(ProtocolKind.VLESS, ProtocolKind.TROJAN, ProtocolKind.SHADOWSOCKS, ProtocolKind.HYSTERIA2, ProtocolKind.SOCKS),
        transports = setOf(
            TransportKind.TCP, TransportKind.WEBSOCKET, TransportKind.GRPC, TransportKind.XHTTP,
            TransportKind.HTTPUPGRADE, TransportKind.NATIVE,
        ),
        securities = setOf(SecurityKind.NONE, SecurityKind.TLS, SecurityKind.REALITY),
        flows = setOf(VlessFlow.NONE, VlessFlow.VISION),
        features = setOf(
            EngineFeature.DOMAIN_RESOLUTION_IF_NO_MATCH,
            EngineFeature.DNS_DOH,
            EngineFeature.DNS_RULES,
            EngineFeature.GEOSITE,
            EngineFeature.GEOIP,
            EngineFeature.TUN_FD,
        ),
    )

    // Теги — часть контракта с проверкой на хосте (tools/xray: решения
    // маршрутизации сверяются по тегам исходящих и правил).
    const val TAG_PROXY: String = "proxy"
    const val TAG_DIRECT: String = "direct"
    const val TAG_BLOCK: String = "block"
    const val TAG_DNS_OUT: String = "dns-out"
    const val TAG_TUN_IN: String = "tun-in"

    /** Локальный прокси подключения без VPN (D-95): один вход на `127.0.0.1`, только без TUN. */
    const val TAG_LOCAL: String = "dppass:local"

    /** Вход раздачи (D-51) — по одному на адрес интерфейса: `dppass:share-0`, `dppass:share-1`… */
    const val SHARE_TAG_PREFIX: String = "dppass:share-"

    /**
     * «Напрямую» для клиентов раздачи (D-51, T11): как `direct`, но не на
     * loopback телефона. Тег — не с [SHARE_TAG_PREFIX]: так помечены только входы.
     */
    const val TAG_DIRECT_SHARE: String = "dppass:direct-share"

    /** Префикс служебных тегов: в id DPpass двоеточия не бывает (`Ids`), совпасть с id пользователя они не могут. */
    const val SYSTEM_PREFIX: String = "dppass:"

    /**
     * Прямой выход, через который исходящий `proxy` открывает соединение с
     * сервером, когда ClientHello разбивается на части (D-68,
     * `streamSettings.sockopt.dialerProxy`).
     */
    const val TAG_SPLIT: String = "${SYSTEM_PREFIX}split"

    /**
     * Прямой выход к сайтам списка «Напрямую с разбиением» (D-72): `freedom`
     * с той же разбивкой начала TLS, что [TAG_SPLIT], и с резолвом имени, как
     * у [TAG_DIRECT].
     */
    const val TAG_DIRECT_SPLIT: String = "${SYSTEM_PREFIX}direct-split"

    /** Теги правил списка «Напрямую с разбиением» (D-72): TCP — на [TAG_DIRECT_SPLIT], UDP 443 — закрыт. */
    const val RULE_SPLIT_SITES: String = "${SYSTEM_PREFIX}split-sites"
    const val RULE_SPLIT_QUIC: String = "${SYSTEM_PREFIX}split-quic"

    /** Тег встроенного DNS-клиента по умолчанию (без него Xray берёт случайный, и конфигурация не повторялась бы). */
    const val TAG_DNS_DEFAULT: String = "${SYSTEM_PREFIX}dns"

    /**
     * MTU и DNS-адрес TUN — те же, что в `TunnelSpecBuilder` (`tunnel/`):
     * `engine` от `tunnel` не зависит, совпадение проверяет
     * `XrayTunnelContractTest` (`tests/integration`).
     */
    const val TUN_MTU: Int = 1500
    const val TUN_DNS4: String = "172.19.0.2"

    /**
     * Имя входа TUN. На Android интерфейс создаёт `VpnService`, ядро берёт
     * только его fd, и имя ни на что не влияет — но без имени Xray при
     * сборке конфигурации подбирает свободное через `net.Interfaces()`, а
     * этот запрос netlink приложениям на Android 11+ запрещён: вход не
     * собирается (`netlinkrib: permission denied`, найдено на устройстве;
     * `docs/research/BACKEND_STRATEGY.md`, §6). Не длиннее 15 символов (IFNAMSIZ).
     */
    const val TUN_NAME: String = "dppass0"

    fun outboundTag(action: RouteAction): String = when (action) {
        RouteAction.PROXY -> TAG_PROXY
        RouteAction.DIRECT -> TAG_DIRECT
        RouteAction.BLOCK -> TAG_BLOCK
    }

    /** Тег запросов одного DNS-сервера: по нему маршрутизация решает, идёт ли запрос через туннель. */
    fun dnsTag(serverId: String): String = "dns:$serverId"
}
