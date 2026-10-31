package com.dpsmpx.dppass.config

import com.dpsmpx.dppass.core.Cidr
import com.dpsmpx.dppass.core.Host
import com.dpsmpx.dppass.diagnostics.DiagCode
import com.dpsmpx.dppass.diagnostics.Diagnostic
import com.dpsmpx.dppass.diagnostics.Secret
import com.dpsmpx.dppass.routing.DnsValidator
import com.dpsmpx.dppass.routing.RoutingValidator
import java.util.Base64

/**
 * Проверка смысла IR, не зависящая от ядра: сочетания протокола,
 * транспорта и защиты, форматы ключей, ссылки, пределы. Что умеет или
 * не умеет конкретное ядро — отдельная проверка возможностей (`engine/`).
 */
object ConfigValidator {
    private val UUID = Regex("""[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}""")
    private val SHORT_ID = Regex("""([0-9a-f]{2}){0,8}""")
    private const val SERVER_NAME_MESSAGE = "имя сервера (server_name; в ссылке — sni) должно быть доменным именем (IDN — в punycode)"
    private const val PLACEHOLDER_MESSAGE = "вместо секрета — метка из отредактированного экспорта; такой профиль не подключится"
    internal const val PATH_MESSAGE = "путь должен начинаться с «/», быть без пробелов и управляющих символов, не длиннее 1024"
    internal const val SERVICE_NAME_MESSAGE = "service_name (в ссылке — serviceName) — непустой, без пробелов, не длиннее 256"

    /**
     * Параметры Hysteria2 формата 3 (D-107) — пределы ядра Xray 26.9.30
     * (`infra/conf/transport_internet.go`, `transport_finalmask.go`): что ядро
     * отвергло бы при запуске, отвергается здесь, с путём.
     */
    private fun hysteria2(proto: ProtocolSpec.Hysteria2, path: String, err: (DiagCode, String, String) -> Unit) {
        val q = proto.quic
        if (proto.congestion == Hysteria2Congestion.FORCE_BRUTAL && q?.brutalUp == null) {
            err(DiagCode.TRANSPORT_SETTING_INVALID, "force-brutal требует скорость отдачи quic.brutal_up", "$path.congestion")
        }
        if (q != null) {
            val at = "$path.quic"
            for ((key, v) in listOf("brutal_up" to q.brutalUp, "brutal_down" to q.brutalDown)) {
                if (v != null && v < Hysteria2Quic.MIN_BRUTAL) err(DiagCode.TRANSPORT_SETTING_INVALID, "скорость Brutal — не меньше 65536 байт/с", "$at.$key")
                if (v != null && v > Hysteria2Quic.MAX_BRUTAL) err(DiagCode.TRANSPORT_SETTING_INVALID, "скорость Brutal — слишком большая", "$at.$key")
            }
            val windows = listOf(
                "init_stream_receive_window" to q.initStreamReceiveWindow,
                "max_stream_receive_window" to q.maxStreamReceiveWindow,
                "init_connection_receive_window" to q.initConnReceiveWindow,
                "max_connection_receive_window" to q.maxConnReceiveWindow,
            )
            for ((key, v) in windows) {
                if (v != null && v < Hysteria2Quic.MIN_WINDOW) err(DiagCode.TRANSPORT_SETTING_INVALID, "окно приёма QUIC — не меньше 16384 байт", "$at.$key")
            }
            q.maxIdleTimeoutSecs?.takeIf { it !in Hysteria2Quic.IDLE_TIMEOUT }?.let {
                err(DiagCode.TRANSPORT_SETTING_INVALID, "max_idle_timeout — от 4 до 120 секунд", "$at.max_idle_timeout")
            }
            q.keepAlivePeriodSecs?.takeIf { it !in Hysteria2Quic.KEEP_ALIVE }?.let {
                err(DiagCode.TRANSPORT_SETTING_INVALID, "keep_alive_period — от 2 до 60 секунд", "$at.keep_alive_period")
            }
        }
        val h = proto.hop ?: return
        if (h.modes.isEmpty()) err(DiagCode.TRANSPORT_SETTING_INVALID, "у перескока портов нет режима", "$path.hop.modes")
        if (h.ports.isEmpty()) err(DiagCode.TRANSPORT_SETTING_INVALID, "у перескока портов нет портов", "$path.hop.ports")
        h.interval?.takeIf { it.from < Hysteria2Hop.MIN_INTERVAL }?.let {
            err(DiagCode.TRANSPORT_SETTING_INVALID, "интервал перескока — не меньше 5 секунд", "$path.hop.interval")
        }
    }

    /**
     * Правила значений транспорта — одни для разбора документа
     * (`DocumentMapper`) и для проверки профиля из любого источника, чтобы
     * они не разошлись.
     */
    internal fun isValidPath(p: String): Boolean =
        p.startsWith("/") && p.length <= 1024 && p.none { it.isWhitespace() || it.code < 0x20 }

    internal fun isValidServiceName(s: String): Boolean =
        s.isNotEmpty() && s.length <= 256 && s.none { it.isWhitespace() }

    fun validate(ir: ConfigIr, limits: ConfigLimits = ConfigLimits()): List<Diagnostic> {
        val out = mutableListOf<Diagnostic>()
        if (ir.profiles.isEmpty()) out += Diagnostic.error(DiagCode.PROFILES_EMPTY, "нет ни одного профиля сервера", "$.profiles")
        if (ir.profiles.size > limits.maxProfiles) {
            out += Diagnostic.error(DiagCode.LIMIT_EXCEEDED, "профилей больше ${limits.maxProfiles}", "$.profiles")
        }
        if (ir.routing.rules.size > limits.maxRules) {
            out += Diagnostic.error(DiagCode.LIMIT_EXCEEDED, "правил больше ${limits.maxRules}", "$.routing.rules")
        }
        val values = ir.routing.rules.sumOf { r ->
            val c = r.conditions
            c.domains.size + c.ipCidrs.size + c.geoSites.size + c.geoIps.size + c.apps.size + c.ports.size
        }
        if (values > limits.maxRuleValues) {
            out += Diagnostic.error(DiagCode.LIMIT_EXCEEDED, "значений в правилах больше ${limits.maxRuleValues}", "$.routing.rules")
        }
        val ids = HashSet<String>()
        for ((i, p) in ir.profiles.withIndex()) {
            val path = "$.profiles[$i]"
            if (!ids.add(p.id.value)) out += Diagnostic.error(DiagCode.ID_DUPLICATE, "повторный id профиля «${p.id}»", "$path.id")
            out += validateProfile(p, path)
        }
        out += RoutingValidator.validate(ir.routing)
        out += DnsValidator.validate(ir.dns)
        return out
    }

    /**
     * Настройки XHTTP формата 2 (D-37) — то, что Xray 26.9.30 отвергает
     * или понимает иначе (`infra/conf/transport_method.go`): нулевое начало
     * у размеров и интервала, `xmux` с обоими пределами. Результат —
     * пары «путь → сообщение».
     */
    internal fun validateXHttpExtra(e: XHttpExtra, path: String): List<Pair<String, String>> {
        val out = mutableListOf<Pair<String, String>>()
        for ((name, r) in listOf(
            "x_padding_bytes" to e.xPaddingBytes,
            "sc_max_each_post_bytes" to e.scMaxEachPostBytes,
            "sc_min_posts_interval_ms" to e.scMinPostsIntervalMs,
        )) {
            if (r != null && r.from < 1) out += "$path.$name" to "«$name» — диапазон с началом не меньше 1"
        }
        val x = e.xmux
        if (x != null) {
            if (x.maxConcurrency != null && x.maxConnections != null) {
                out += "$path.xmux.max_connections" to "max_concurrency и max_connections не задаются вместе (Xray отвергает такую настройку)"
            }
            if (x.hKeepAlivePeriod != null && x.hKeepAlivePeriod !in -1..86_400) {
                out += "$path.xmux.h_keep_alive_period" to "h_keep_alive_period — секунды от -1 до 86400"
            }
        }
        return out
    }

    /**
     * Проверка одного профиля — и для документа, и для записи подписки.
     *
     * Запись подписки приходит мимо `DocumentMapper` (ссылка → IR напрямую),
     * поэтому всё, что определяет смысл профиля, проверяется здесь, даже
     * если разбор документа уже проверил то же самое: один и тот же профиль
     * не может быть верным ссылкой и неверным документом (D-05). Так —
     * имя сервера, `host`, путь и `service_name` транспорта.
     */
    fun validateProfile(p: ServerProfile, path: String): List<Diagnostic> {
        val out = mutableListOf<Diagnostic>()
        fun err(code: DiagCode, msg: String, at: String) {
            out += Diagnostic.error(code, msg, at)
        }

        fun secretPresent(s: Secret, at: String): Boolean {
            if (s.isEmpty) {
                err(DiagCode.PASSWORD_EMPTY, "пустое секретное значение", at)
                return false
            }
            if (s.reveal() == Secret.REDACTED) {
                err(DiagCode.SECRET_PLACEHOLDER, PLACEHOLDER_MESSAGE, at)
                return false
            }
            return true
        }

        when (val proto = p.protocol) {
            is ProtocolSpec.Vless -> {
                if (secretPresent(proto.id, "$path.protocol.id") && !UUID.matches(proto.id.reveal())) {
                    err(DiagCode.UUID_INVALID, "id VLESS должен быть UUID", "$path.protocol.id")
                }
                if (p.security is SecuritySpec.None) {
                    err(DiagCode.SECURITY_REQUIRED, "VLESS без TLS или REALITY передаёт данные открыто", "$path.security")
                }
                if (proto.flow == VlessFlow.VISION && (p.transport !is TransportSpec.Tcp || p.security is SecuritySpec.None)) {
                    err(DiagCode.FLOW_REQUIRES_TCP_TLS, "flow vision работает только поверх TCP с TLS или REALITY", "$path.protocol.flow")
                }
            }
            is ProtocolSpec.Trojan -> {
                secretPresent(proto.password, "$path.protocol.password")
                if (p.security !is SecuritySpec.Tls) err(DiagCode.SECURITY_REQUIRED, "Trojan требует TLS", "$path.security")
            }
            is ProtocolSpec.Shadowsocks -> {
                if (secretPresent(proto.password, "$path.protocol.password")) {
                    val need = if (proto.method == ShadowsocksMethod.BLAKE3_AES_128_GCM) 16 else 32
                    val decoded = runCatching { Base64.getDecoder().decode(proto.password.reveal()) }.getOrNull()
                    if (decoded == null || decoded.size != need) {
                        err(DiagCode.PASSWORD_FORMAT_INVALID, "для ${proto.method.wire} пароль — ключ base64 длиной $need байт", "$path.protocol.password")
                    }
                }
                if (p.security !is SecuritySpec.None) {
                    err(DiagCode.TRANSPORT_PROTOCOL_MISMATCH, "Shadowsocks шифрует сам: security должно быть none", "$path.security")
                }
                if (p.transport !is TransportSpec.Tcp) {
                    err(DiagCode.TRANSPORT_PROTOCOL_MISMATCH, "Shadowsocks в IR v1 — только поверх tcp", "$path.transport")
                }
            }
            is ProtocolSpec.Hysteria2 -> {
                secretPresent(proto.password, "$path.protocol.password")
                proto.obfsPassword?.let { secretPresent(it, "$path.protocol.obfs_password") }
                if (p.transport !is TransportSpec.Native) {
                    err(DiagCode.TRANSPORT_PROTOCOL_MISMATCH, "Hysteria2 работает поверх своего QUIC: transport должен быть native", "$path.transport")
                }
                if (p.security !is SecuritySpec.Tls) err(DiagCode.SECURITY_REQUIRED, "Hysteria2 требует TLS", "$path.security")
                hysteria2(proto, "$path.protocol", ::err)
            }
            is ProtocolSpec.Socks -> {
                secretPresent(proto.user, "$path.protocol.user")
                secretPresent(proto.password, "$path.protocol.password")
                val ip = (p.endpoint.host as? Host.Ip)?.address
                if (ip == null || !Cidr.isPrivateV4(ip)) {
                    err(
                        DiagCode.RELAY_ADDRESS_NOT_LOCAL,
                        "устройство раздачи — только частный IPv4-адрес своей сети (RFC 1918): SOCKS передаёт логин, пароль и трафик открыто",
                        "$path.server",
                    )
                }
                if (p.transport !is TransportSpec.Tcp) err(DiagCode.TRANSPORT_PROTOCOL_MISMATCH, "SOCKS — только поверх tcp", "$path.transport")
                if (p.security !is SecuritySpec.None) {
                    err(DiagCode.TRANSPORT_PROTOCOL_MISMATCH, "вход раздачи — без TLS: security должно быть none", "$path.security")
                }
            }
        }
        if (p.transport is TransportSpec.Native && p.protocol !is ProtocolSpec.Hysteria2) {
            err(DiagCode.TRANSPORT_PROTOCOL_MISMATCH, "transport native — только у Hysteria2", "$path.transport")
        }
        when (val sec = p.security) {
            is SecuritySpec.Reality -> {
                if (p.protocol !is ProtocolSpec.Vless) {
                    err(DiagCode.TRANSPORT_PROTOCOL_MISMATCH, "REALITY в IR v1 — только с VLESS", "$path.security")
                }
                if (p.transport !is TransportSpec.Tcp && p.transport !is TransportSpec.XHttp && p.transport !is TransportSpec.Grpc) {
                    err(DiagCode.TRANSPORT_PROTOCOL_MISMATCH, "REALITY работает поверх tcp, xhttp или grpc", "$path.transport")
                }
                val key = runCatching { Base64.getUrlDecoder().decode(sec.publicKey) }.getOrNull()
                if (sec.publicKey.length != 43 || key == null || key.size != 32) {
                    err(DiagCode.REALITY_PUBLIC_KEY_INVALID, "public_key — 32 байта X25519 в base64url без «=» (43 символа)", "$path.security.public_key")
                }
                // short_id в экспорте без секретов — тоже метка (D-11): причина — она, а не «не шестнадцатеричное».
                val shortId = sec.shortId.reveal()
                if (shortId == Secret.REDACTED) {
                    err(DiagCode.SECRET_PLACEHOLDER, PLACEHOLDER_MESSAGE, "$path.security.short_id")
                } else if (!SHORT_ID.matches(shortId)) {
                    err(DiagCode.REALITY_SHORT_ID_INVALID, "short_id — чётное число шестнадцатеричных цифр в нижнем регистре, до 16", "$path.security.short_id")
                }
                if (Host.normalizeDomain(sec.serverName) == null) {
                    err(DiagCode.SERVER_NAME_INVALID, SERVER_NAME_MESSAGE, "$path.security.server_name")
                }
            }
            is SecuritySpec.Tls -> {
                if (sec.alpn.any { it.isEmpty() || it.length > 32 }) {
                    err(DiagCode.FIELD_TYPE, "значение alpn пустое или длиннее 32 символов", "$path.security.alpn")
                }
                if (sec.serverName != null && Host.normalizeDomain(sec.serverName) == null) {
                    err(DiagCode.SERVER_NAME_INVALID, SERVER_NAME_MESSAGE, "$path.security.server_name")
                }
            }
            SecuritySpec.None -> Unit
        }
        val (transportPath, hostHeader) = when (val t = p.transport) {
            is TransportSpec.WebSocket -> t.path to t.host
            is TransportSpec.HttpUpgrade -> t.path to t.host
            is TransportSpec.XHttp -> t.path to t.host
            is TransportSpec.Grpc -> {
                if (!isValidServiceName(t.serviceName)) err(DiagCode.PATH_INVALID, SERVICE_NAME_MESSAGE, "$path.transport.service_name")
                null to null
            }
            TransportSpec.Tcp, TransportSpec.Native -> null to null
        }
        (p.transport as? TransportSpec.XHttp)?.extra?.let { e ->
            validateXHttpExtra(e, "$path.transport").forEach {
                err(DiagCode.TRANSPORT_SETTING_INVALID, it.second, it.first)
            }
        }
        if (transportPath != null && !isValidPath(transportPath)) {
            err(DiagCode.PATH_INVALID, PATH_MESSAGE, "$path.transport.path")
        }
        if (hostHeader != null && Host.normalizeDomain(hostHeader) == null) {
            err(DiagCode.DOMAIN_INVALID, "host должен быть доменным именем (IDN — в punycode)", "$path.transport.host")
        }
        return out
    }
}
