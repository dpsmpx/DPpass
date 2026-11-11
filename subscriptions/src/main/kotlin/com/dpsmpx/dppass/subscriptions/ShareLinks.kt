package com.dpsmpx.dppass.subscriptions

import com.dpsmpx.dppass.config.BbrProfile
import com.dpsmpx.dppass.config.CandidateHints
import com.dpsmpx.dppass.config.CountRange
import com.dpsmpx.dppass.config.HopMode
import com.dpsmpx.dppass.config.Hysteria2Congestion
import com.dpsmpx.dppass.config.Hysteria2Hop
import com.dpsmpx.dppass.config.Hysteria2Quic
import com.dpsmpx.dppass.config.ProtocolSpec
import com.dpsmpx.dppass.config.SecuritySpec
import com.dpsmpx.dppass.config.ServerProfile
import com.dpsmpx.dppass.config.ShadowsocksMethod
import com.dpsmpx.dppass.config.TlsFingerprint
import com.dpsmpx.dppass.config.TransportSpec
import com.dpsmpx.dppass.config.VlessFlow
import com.dpsmpx.dppass.config.XHttpExtra
import com.dpsmpx.dppass.config.XHttpMode
import com.dpsmpx.dppass.config.Xmux
import com.dpsmpx.dppass.core.Checksums
import com.dpsmpx.dppass.core.Endpoint
import com.dpsmpx.dppass.core.Host
import com.dpsmpx.dppass.core.Json
import com.dpsmpx.dppass.core.JsonArray
import com.dpsmpx.dppass.core.JsonBool
import com.dpsmpx.dppass.core.JsonNumber
import com.dpsmpx.dppass.core.JsonObject
import com.dpsmpx.dppass.core.JsonParseException
import com.dpsmpx.dppass.core.JsonString
import com.dpsmpx.dppass.core.PortRange
import com.dpsmpx.dppass.core.ProfileId
import com.dpsmpx.dppass.diagnostics.DiagCode
import com.dpsmpx.dppass.diagnostics.Diagnostic
import com.dpsmpx.dppass.diagnostics.Outcome
import com.dpsmpx.dppass.diagnostics.Secret
import java.util.Base64

/**
 * Ссылки вида `vless://…`, `trojan://…`, `hysteria2://…` (`hy2://…`) и
 * `ss://…` (только Shadowsocks-2022, D-16) → профиль IR.
 *
 * Это чужой формат без строгой спецификации, поэтому правило строже
 * обычного: известный параметр переводится в IR; известный «по
 * умолчанию» (например, `encryption=none`) принимается; **любой другой
 * параметр делает ссылку непригодной** с предупреждением и списком
 * имён. Иначе профиль подключался бы не так, как задумал поставщик, —
 * это молчаливая потеря смысла (D-05). Список растёт вместе с IR.
 *
 * Сообщения не содержат значений параметров и самой ссылки: в них
 * UUID и ключи.
 */
object ShareLinkParser {
    private val SUPPORTED = setOf("vless", "trojan", "hysteria2", "hy2", "ss")
    private val KNOWN_OTHER = setOf("vmess", "tuic", "wireguard", "wg", "socks", "http", "https", "anytls", "naive+https")

    private val HYSTERIA2_PARAMS = setOf("sni", "obfs", "obfs-password", "insecure", "fm")

    /** Старые AEAD Shadowsocks: без защиты от повтора, в IR v1 их нет (D-16). */
    private val SS_LEGACY = setOf(
        "aes-128-gcm", "aes-192-gcm", "aes-256-gcm", "chacha20-ietf-poly1305", "chacha20-poly1305",
        "xchacha20-ietf-poly1305", "xchacha20-poly1305",
    )

    private val VLESS_PARAMS = setOf(
        "type", "security", "sni", "fp", "pbk", "sid", "spx", "flow", "path", "host", "servicename", "mode", "alpn", "encryption",
        "headertype", "allowinsecure", "insecure", "extra",
    )
    private val TROJAN_PARAMS = setOf(
        "type", "security", "sni", "fp", "path", "host", "servicename", "mode", "alpn", "headertype", "allowinsecure", "insecure", "extra",
    )

    /**
     * Ключи `fm.quicParams`, которые отбрасываются с находкой (D-48): по
     * исходникам Xray 26.9.30 на соединение не влияют. Только поимённо —
     * всё прочее по-прежнему отказ (D-05).
     */
    private val QUIC_IGNORED = listOf("debug", "maxIncomingStreams", "disableStatelessReset")

    /** Ключи `fm.quicParams`, которые выражает IR (формат 2 и 3, D-37, D-107). */
    private val WINDOW_KEYS = listOf("initStreamReceiveWindow", "maxStreamReceiveWindow", "initConnectionReceiveWindow", "maxConnectionReceiveWindow")
    private val FLAG_KEYS = listOf("brutalDisableLossCompensation", "disablePathMTUDiscovery", "disableChromeParrot", "disableGSO")
    private val QUIC_KEYS = setOf("congestion", "bbrProfile", "brutalUp", "brutalDown", "maxIdleTimeout", "keepAlivePeriod") + WINDOW_KEYS + FLAG_KEYS

    /** Ключи настроек маски `udphop`, которые выражает IR (D-107). */
    private val HOP_KEYS = setOf("mode", "interval", "remotePorts")

    /** Ключи `extra` XHTTP, которые выражает IR (формат 2, D-37); прочие — отказ с названием. */
    private val XHTTP_EXTRA = setOf("xPaddingBytes", "scMaxEachPostBytes", "scMinPostsIntervalMs", "noGRPCHeader", "xmux")
    private val XMUX = setOf("maxConcurrency", "maxConnections", "cMaxReuseTimes", "hMaxRequestTimes", "hMaxReusableSecs", "hKeepAlivePeriod")

    fun isLink(line: String): Boolean = SCHEME.find(line.trim())?.range?.first == 0

    /** [idPrefix] — префикс устойчивых id (обычно id подписки). */
    fun parse(link: String, idPrefix: String): Outcome<ServerProfile> {
        val text = link.trim()
        val scheme = SCHEME.find(text)?.groupValues?.get(1)?.lowercase()
            ?: return Outcome.failure(DiagCode.SHARE_LINK_INVALID, "не ссылка вида схема://…")
        if (scheme !in SUPPORTED) {
            val known = if (scheme in KNOWN_OTHER) "ещё не поддерживается" else "неизвестна"
            return Outcome.Failure(
                listOf(
                    Diagnostic.error(DiagCode.SHARE_LINK_INVALID, "схема $scheme://").withCause(
                        Diagnostic.warning(DiagCode.SHARE_LINK_SCHEME_UNSUPPORTED, "схема $scheme:// $known"),
                    ),
                ),
            )
        }
        val parts = split(text.substring(scheme.length + 3))
            ?: return Outcome.failure(DiagCode.SHARE_LINK_INVALID, "ссылка $scheme:// без «секрет@хост:порт»")
        val host = Host.parse(parts.host) ?: return Outcome.failure(DiagCode.SHARE_LINK_INVALID, "адрес сервера — не домен и не IP")
        val port = parts.port.toIntOrNull()?.takeIf { it in 1..65535 }
            ?: return Outcome.failure(DiagCode.SHARE_LINK_INVALID, "порт вне 1..65535")
        val endpoint = Endpoint(host, port)
        when (scheme) {
            "hysteria2", "hy2" -> return hysteria2(text, parts, endpoint, idPrefix)
            "ss" -> return shadowsocks(text, parts, endpoint, idPrefix)
        }
        val q = parts.query
        val known = if (scheme == "vless") VLESS_PARAMS else TROJAN_PARAMS
        // `fm` без масок — то же, что без него; с масками — отказ с их именами (D-107).
        val fm = q["fm"]?.takeUnless { emptyFinalMask(it) }
        val unknown = q.keys.filter { it !in known && it != "fm" } + listOfNotNull(fm?.let(::finalMaskNames))
        if (unknown.isNotEmpty()) return unsupported(unknown.sorted().joinToString())
        if (q["encryption"].let { it != null && it != "none" }) return unsupported("encryption (кроме none)")
        if (q["headertype"].let { it != null && it != "none" }) return unsupported("headerType (кроме none)")
        if (q["allowinsecure"] in setOf("1", "true") || q["insecure"] in setOf("1", "true")) {
            return Outcome.failure(DiagCode.INSECURE_TLS_REJECTED, "ссылка отключает проверку сертификата — такой профиль не принимается")
        }

        val hostHeader = domainParam(q["host"])
        // Пустое значение — как отсутствие параметра; неверный путь или serviceName остаётся
        // как есть — его отвергает ConfigValidator.validateProfile с путём, как и у документа.
        val path = q["path"]?.takeIf { it.isNotEmpty() } ?: "/"
        val transport = when (val type = q["type"] ?: "tcp") {
            "tcp", "raw" -> TransportSpec.Tcp
            "ws" -> TransportSpec.WebSocket(path, hostHeader)
            "httpupgrade" -> TransportSpec.HttpUpgrade(path, hostHeader)
            "grpc" -> TransportSpec.Grpc(
                q["servicename"]?.takeIf { it.isNotEmpty() } ?: return Outcome.failure(DiagCode.SHARE_LINK_INVALID, "grpc без serviceName"),
            )
            "xhttp", "splithttp" -> {
                val mode = XHttpMode.entries.firstOrNull { it.wire == (q["mode"] ?: "auto") } ?: return unsupported("mode")
                val extra = when (val e = q["extra"]?.takeIf { it.isNotEmpty() }?.let(::xhttpExtra)) {
                    null -> XHttpExtra.NONE
                    is Outcome.Failure -> return e
                    is Outcome.Success -> e.value
                }
                TransportSpec.XHttp(path, hostHeader, mode, extra)
            }
            else -> return unsupported("type")
        }
        if (q["extra"].let { !it.isNullOrEmpty() } && transport !is TransportSpec.XHttp) return unsupported("extra (только у xhttp)")
        val fp = q["fp"]?.let { f -> TlsFingerprint.entries.firstOrNull { it.wire == f } ?: return unsupported("fp") }
        val sni = domainParam(q["sni"])
        val security = when (val s = q["security"] ?: if (scheme == "trojan") "tls" else "none") {
            "none" -> SecuritySpec.None
            "tls" -> SecuritySpec.Tls(sni, q["alpn"]?.split(',')?.map { it.trim() }?.filter { it.isNotEmpty() } ?: emptyList(), fp)
            "reality" -> SecuritySpec.Reality(
                serverName = sni ?: return Outcome.failure(DiagCode.SHARE_LINK_INVALID, "reality без sni"),
                publicKey = q["pbk"] ?: return Outcome.failure(DiagCode.SHARE_LINK_INVALID, "reality без pbk"),
                shortId = Secret(q["sid"] ?: ""),
                fingerprint = fp ?: TlsFingerprint.CHROME,
                spiderX = q["spx"],
            )
            else -> return unsupported("security")
        }
        val secret = Secret(parts.user)
        val protocol = if (scheme == "vless") {
            val flow = when (q["flow"]) {
                null, "", "none" -> VlessFlow.NONE
                "xtls-rprx-vision" -> VlessFlow.VISION
                else -> return unsupported("flow")
            }
            ProtocolSpec.Vless(secret, flow)
        } else {
            ProtocolSpec.Trojan(secret)
        }
        return Outcome.Success(profile(text, parts, endpoint, idPrefix, protocol, transport, security))
    }

    /**
     * `hysteria2://пароль@хост:порт/?sni=…&obfs=salamander&obfs-password=…#имя`.
     * Пароль — вся часть до «@» (в нём бывает «:»). Защита — всегда TLS;
     * ALPN и отпечаток у Hysteria2 не задаются (`docs/CONFIG_FORMAT.md`, §3).
     * Порт — один: диапазоны портов IR не выражает.
     */
    private fun hysteria2(text: String, parts: Parts, endpoint: Endpoint, idPrefix: String): Outcome<ServerProfile> {
        val q = parts.query
        val unknown = q.keys.filter { it !in HYSTERIA2_PARAMS }
        if (unknown.isNotEmpty()) return unsupported(unknown.sorted().joinToString())
        if (q["insecure"] in setOf("1", "true")) {
            return Outcome.failure(DiagCode.INSECURE_TLS_REJECTED, "ссылка отключает проверку сертификата — такой профиль не принимается")
        }
        if (q["insecure"].let { it != null && it !in setOf("0", "false") }) return unsupported("insecure (кроме 0)")
        val obfs = q["obfs"]?.takeIf { it.isNotEmpty() }
        val obfsPassword = q["obfs-password"]?.takeIf { it.isNotEmpty() }
        if (obfs != null && obfs != "salamander") return unsupported("obfs (кроме salamander)")
        if ((obfs == null) != (obfsPassword == null)) {
            return Outcome.failure(DiagCode.SHARE_LINK_INVALID, "obfs и obfs-password задаются только вместе")
        }
        val mask = when (val c = q["fm"]?.takeIf { it.isNotEmpty() }?.let(::finalMask)) {
            null -> null
            is Outcome.Failure -> return c
            is Outcome.Success -> c
        }
        val fm = mask?.value
        if (fm?.salamander != null && obfsPassword != null && fm.salamander != obfsPassword) {
            return Outcome.failure(DiagCode.SHARE_LINK_INVALID, "у obfs-password и маски salamander в fm разные пароли")
        }
        val salamander = obfsPassword ?: fm?.salamander
        val protocol = ProtocolSpec.Hysteria2(Secret(parts.user), salamander?.let(::Secret), fm?.congestion, fm?.quic, fm?.hop)
        val security = SecuritySpec.Tls(domainParam(q["sni"]), emptyList(), null)
        return Outcome.Success(profile(text, parts, endpoint, idPrefix, protocol, TransportSpec.Native, security), mask?.diagnostics.orEmpty())
    }

    /**
     * `ss://ДАННЫЕ@хост:порт#имя`, где ДАННЫЕ — `метод:пароль` в base64
     * (стандартный или для URL, с дополнением или без) либо открыто с
     * %-кодированием (SIP002). Только методы Shadowsocks-2022; старый AEAD
     * и параметры (`plugin` и др.) — отказ с названием (D-16, D-05).
     */
    private fun shadowsocks(text: String, parts: Parts, endpoint: Endpoint, idPrefix: String): Outcome<ServerProfile> {
        if (parts.query.isNotEmpty()) return unsupported(parts.query.keys.sorted().joinToString())
        val credentials = if (':' in parts.user) {
            parts.user
        } else {
            decodeBase64(parts.user)
                ?: return Outcome.failure(DiagCode.SHARE_LINK_INVALID, "ss:// без «метод:пароль» (ни открыто, ни в base64)")
        }
        val method = credentials.substringBefore(':')
        val password = credentials.substringAfter(':', "")
        if (method == credentials || password.isEmpty()) {
            return Outcome.failure(DiagCode.SHARE_LINK_INVALID, "ss:// без «метод:пароль»")
        }
        // Имя метода повторяется в сообщении, только если оно известно: в испорченной
        // ссылке до «:» может стоять секрет, а сообщения значений из ссылки не содержат.
        val ss = ShadowsocksMethod.entries.firstOrNull { it.wire == method.lowercase() }
            ?: return unsupported(
                if (method.lowercase() in SS_LEGACY) "method=${method.lowercase()} (старый AEAD без защиты от повтора, D-16)" else "method (неизвестный метод)",
            )
        val protocol = ProtocolSpec.Shadowsocks(ss, Secret(password))
        return Outcome.Success(profile(text, parts, endpoint, idPrefix, protocol, TransportSpec.Tcp, SecuritySpec.None))
    }

    /**
     * `extra` XHTTP — JSON настроек Xray (`SplitHTTPConfig`). Принимаются
     * только ключи [XHTTP_EXTRA] и [XMUX]; значение диапазона — целое или
     * строка «N-M», «0» — то же, что ключа нет (так понимает Xray). Смысл
     * значений (не меньше 1, `xmux` без обоих пределов) проверяет
     * `ConfigValidator.validateProfile`, как у документа.
     */
    private fun xhttpExtra(text: String): Outcome<XHttpExtra> {
        val root = json(text) ?: return Outcome.failure(DiagCode.SHARE_LINK_INVALID, "extra — не объект JSON")
        val unknown = root.fields.keys.filter { it !in XHTTP_EXTRA }.map { "extra.$it" }.toMutableList()
        val xmuxObj = root["xmux"]
        if (xmuxObj != null && xmuxObj !is JsonObject) return Outcome.failure(DiagCode.SHARE_LINK_INVALID, "extra.xmux — не объект")
        xmuxObj?.fields?.keys?.filter { it !in XMUX }?.forEach { unknown += "extra.xmux.$it" }
        if (unknown.isNotEmpty()) return unsupported(unknown.sorted().joinToString())

        var bad: String? = null
        fun range(o: JsonObject, key: String, at: String): CountRange? {
            val r = when (val v = o[key]) {
                null -> return null
                is JsonNumber -> v.toIntOrNull()?.takeIf { it >= 0 }?.let { CountRange(it, it) }
                is JsonString -> CountRange.parse(v.value)
                else -> null
            }
            if (r == null) bad = bad ?: at
            return r?.takeUnless { it.from == 0 && it.to == 0 }
        }
        val xmux = xmuxObj?.let { x ->
            val keepAlive = when (val v = x["hKeepAlivePeriod"]) {
                null -> null
                is JsonNumber -> v.toIntOrNull()?.takeIf { it in -1..86_400 } ?: null.also { bad = bad ?: "extra.xmux.hKeepAlivePeriod" }
                else -> null.also { bad = bad ?: "extra.xmux.hKeepAlivePeriod" }
            }
            Xmux(
                maxConcurrency = range(x, "maxConcurrency", "extra.xmux.maxConcurrency"),
                maxConnections = range(x, "maxConnections", "extra.xmux.maxConnections"),
                cMaxReuseTimes = range(x, "cMaxReuseTimes", "extra.xmux.cMaxReuseTimes"),
                hMaxRequestTimes = range(x, "hMaxRequestTimes", "extra.xmux.hMaxRequestTimes"),
                hMaxReusableSecs = range(x, "hMaxReusableSecs", "extra.xmux.hMaxReusableSecs"),
                hKeepAlivePeriod = keepAlive?.takeIf { it != 0 },
            ).takeUnless { it.isEmpty }
        }
        val noGrpc = when (val v = root["noGRPCHeader"]) {
            null -> false
            is JsonBool -> v.value
            else -> false.also { bad = bad ?: "extra.noGRPCHeader" }
        }
        val extra = XHttpExtra(
            xPaddingBytes = range(root, "xPaddingBytes", "extra.xPaddingBytes"),
            scMaxEachPostBytes = range(root, "scMaxEachPostBytes", "extra.scMaxEachPostBytes"),
            scMinPostsIntervalMs = range(root, "scMinPostsIntervalMs", "extra.scMinPostsIntervalMs"),
            noGrpcHeader = noGrpc,
            xmux = xmux,
        )
        bad?.let {
            return Outcome.failure(DiagCode.SHARE_LINK_INVALID, "$it — не диапазон «N» или «N-M» (или не того типа)")
        }
        return Outcome.Success(extra)
    }

    /** Что взято из `fm` Hysteria2 (D-37, D-107). */
    private class FinalMask(
        val congestion: Hysteria2Congestion?,
        val quic: Hysteria2Quic?,
        val hop: Hysteria2Hop?,
        /** Пароль маски Salamander из `fm.udp` — то же, что `obfs-password`. */
        val salamander: String?,
    )

    /**
     * `fm` у Hysteria2 — finalmask Xray 26.9.30 в JSON (D-37, D-107):
     * - `quicParams` — управление перегрузкой и параметры QUIC, которые
     *   действуют у клиента (`transport/internet/hysteria/dialer.go`);
     *   `debug` и серверные `maxIncomingStreams`, `disableStatelessReset`
     *   (только `hub.go`) отбрасываются с находкой (D-48);
     * - `udp` — маски `salamander` (без `packetSize`) и `udphop` (без
     *   `remoteIPs`: сервер в IR — один адрес).
     * Прочее — отказ с названием (D-05). Значения в сообщениях не
     * цитируются: в масках бывают пароли.
     */
    private fun finalMask(text: String): Outcome<FinalMask> {
        val root = json(text) ?: return Outcome.failure(DiagCode.SHARE_LINK_INVALID, "fm — не объект JSON")
        val unknown = root.fields.keys.filter { it != "quicParams" && it != "udp" }.map { "fm.$it" }.toMutableList()
        val quic = root["quicParams"]
        if (quic != null && quic !is JsonObject) return Outcome.failure(DiagCode.SHARE_LINK_INVALID, "fm.quicParams — не объект")
        quic?.fields?.keys?.filter { it !in QUIC_KEYS && it !in QUIC_IGNORED }?.forEach { unknown += "fm.quicParams.$it" }
        val udp = root["udp"]
        if (udp != null && udp !is JsonArray) return Outcome.failure(DiagCode.SHARE_LINK_INVALID, "fm.udp — не массив")
        val masks = udp?.items.orEmpty()
        for ((i, m) in masks.withIndex()) {
            val o = m as? JsonObject ?: return Outcome.failure(DiagCode.SHARE_LINK_INVALID, "fm.udp[$i] — не объект")
            val type = (o["type"] as? JsonString)?.value ?: return Outcome.failure(DiagCode.SHARE_LINK_INVALID, "fm.udp[$i].type — не строка")
            o.fields.keys.filter { it != "type" && it != "settings" }.forEach { unknown += "fm.udp[$i].$it" }
            val settings = o["settings"] as? JsonObject
            if (o["settings"] != null && settings == null) return Outcome.failure(DiagCode.SHARE_LINK_INVALID, "fm.udp[$i].settings — не объект")
            when (type) {
                "salamander" -> settings?.fields?.keys?.filter { it != "password" }?.forEach { unknown += "fm.udp[$i].settings.$it" }
                "udphop" -> settings?.fields?.keys?.filter { it !in HOP_KEYS }?.forEach { unknown += "fm.udp[$i].settings.$it" }
                else -> unknown += if (MASK_TYPE.matches(type)) "fm.udp[$i] (маска $type)" else "fm.udp[$i]"
            }
        }
        if (unknown.isNotEmpty()) return unsupported(unknown.sorted().joinToString())
        val notes = mutableListOf<Diagnostic>()
        for (key in QUIC_IGNORED) {
            val v = quic?.get(key) ?: continue
            if (v !is JsonBool && v !is JsonNumber) return Outcome.failure(DiagCode.SHARE_LINK_INVALID, "fm.quicParams.$key — не того типа")
            notes += Diagnostic.info(DiagCode.SHARE_LINK_PARAM_IGNORED, "fm.quicParams.$key отброшен: на соединение клиента не влияет (D-48)")
        }
        val q = quic ?: JsonObject(emptyMap())
        fun bad(key: String, what: String): Outcome.Failure = Outcome.failure(DiagCode.SHARE_LINK_INVALID, "fm.quicParams.$key — $what")
        fun flag(key: String): Boolean? = when (val v = q[key]) {
            null -> false
            is JsonBool -> v.value
            else -> null
        }
        fun count(key: String): Long? = when (val v = q[key]) {
            null -> 0
            is JsonNumber -> v.toLongOrNull()?.takeIf { it >= 0 }
            else -> null
        }
        val congestion = when (val v = q["congestion"]) {
            null -> null
            is JsonString -> v.value.lowercase().ifEmpty { null }?.let { name ->
                Hysteria2Congestion.entries.firstOrNull { it.wire == name } ?: return bad("congestion", "не bbr, reno, brutal или force-brutal")
            }
            else -> return bad("congestion", "не строка")
        }
        val profile = when (val v = q["bbrProfile"]) {
            null -> null
            is JsonString -> v.value.lowercase().ifEmpty { null }?.let { name ->
                BbrProfile.entries.firstOrNull { it.wire == name } ?: return bad("bbrProfile", "не conservative, standard или aggressive")
            }
            else -> return bad("bbrProfile", "не строка")
        }
        fun speed(key: String): Outcome<Long?> = when (val v = q[key]) {
            null -> Outcome.Success(null)
            is JsonString -> bandwidth(v.value)?.let { Outcome.Success(it.takeIf { b -> b > 0 }) }
                ?: bad(key, "скорость не понята (число и b, k, m, g, t или с bps)")
            else -> bad(key, "не строка")
        }
        val up = when (val r = speed("brutalUp")) {
            is Outcome.Failure -> return r
            is Outcome.Success -> r.value
        }
        val down = when (val r = speed("brutalDown")) {
            is Outcome.Failure -> return r
            is Outcome.Success -> r.value
        }
        val numbers = WINDOW_KEYS.associateWith { k -> count(k) ?: return bad(k, "не целое без знака") }
        val idle = count("maxIdleTimeout") ?: return bad("maxIdleTimeout", "не целое без знака")
        val keepAlive = count("keepAlivePeriod") ?: return bad("keepAlivePeriod", "не целое без знака")
        val flags = FLAG_KEYS.associateWith { k -> flag(k) ?: return bad(k, "не true/false") }
        val quicSpec = Hysteria2Quic(
            bbrProfile = profile,
            brutalUp = up,
            brutalDown = down,
            brutalDisableLossCompensation = flags.getValue("brutalDisableLossCompensation"),
            initStreamReceiveWindow = numbers.getValue("initStreamReceiveWindow").takeIf { it > 0 },
            maxStreamReceiveWindow = numbers.getValue("maxStreamReceiveWindow").takeIf { it > 0 },
            initConnReceiveWindow = numbers.getValue("initConnectionReceiveWindow").takeIf { it > 0 },
            maxConnReceiveWindow = numbers.getValue("maxConnectionReceiveWindow").takeIf { it > 0 },
            maxIdleTimeoutSecs = idle.takeIf { it > 0 }?.coerceAtMost(Int.MAX_VALUE.toLong())?.toInt(),
            keepAlivePeriodSecs = keepAlive.takeIf { it > 0 }?.coerceAtMost(Int.MAX_VALUE.toLong())?.toInt(),
            disablePathMtuDiscovery = flags.getValue("disablePathMTUDiscovery"),
            disableChromeParrot = flags.getValue("disableChromeParrot"),
            disableGso = flags.getValue("disableGSO"),
        )
        var salamander: String? = null
        var hop: Hysteria2Hop? = null
        for ((i, m) in masks.withIndex()) {
            val o = m as JsonObject
            val settings = o["settings"] as? JsonObject ?: JsonObject(emptyMap())
            when ((o["type"] as JsonString).value) {
                "salamander" -> {
                    val pw = (settings["password"] as? JsonString)?.value?.takeIf { it.isNotEmpty() }
                        ?: return Outcome.failure(DiagCode.SHARE_LINK_INVALID, "fm.udp[$i]: у маски salamander нет пароля")
                    if (salamander != null) return Outcome.failure(DiagCode.SHARE_LINK_INVALID, "fm.udp: маска salamander повторяется")
                    salamander = pw
                }
                "udphop" -> {
                    if (hop != null) return Outcome.failure(DiagCode.SHARE_LINK_INVALID, "fm.udp: маска udphop повторяется")
                    hop = when (val h = udpHop(settings, "fm.udp[$i].settings")) {
                        is Outcome.Failure -> return h
                        is Outcome.Success -> h.value
                    }
                }
            }
        }
        return Outcome.Success(FinalMask(congestion, quicSpec.takeUnless { it.isEmpty }, hop, salamander), notes)
    }

    /** Маска `udphop` (D-107): режимы, порты сервера, интервал — как их читает Xray (`infra/conf/transport_finalmask.go`). */
    private fun udpHop(s: JsonObject, at: String): Outcome<Hysteria2Hop> {
        val mode = (s["mode"] as? JsonString)?.value ?: return Outcome.failure(DiagCode.SHARE_LINK_INVALID, "$at.mode — нет режима перескока")
        val modes = mode.split(',').map { m ->
            HopMode.entries.firstOrNull { it.xray.equals(m.trim(), ignoreCase = true) }
                ?: return Outcome.failure(DiagCode.SHARE_LINK_INVALID, "$at.mode — не intervalLocal, intervalRemote или perConnRemote")
        }.toSet()
        val ports = when (val v = s["remotePorts"]) {
            is JsonString -> v.value.split(',').map { it.trim() }.filter { it.isNotEmpty() }.map { part ->
                PortRange.parse(part) ?: return Outcome.failure(DiagCode.SHARE_LINK_INVALID, "$at.remotePorts — порт или диапазон 1…65535")
            }
            is JsonNumber -> listOfNotNull(v.toIntOrNull()?.takeIf { it in 1..65535 }?.let { PortRange(it, it) })
            else -> emptyList()
        }
        if (ports.isEmpty()) return Outcome.failure(DiagCode.SHARE_LINK_INVALID, "$at.remotePorts — нет портов сервера")
        val interval = when (val v = s["interval"]) {
            null -> null
            is JsonNumber -> v.toIntOrNull()?.takeIf { it >= 0 }?.let { CountRange(it, it) }
                ?: return Outcome.failure(DiagCode.SHARE_LINK_INVALID, "$at.interval — не целое без знака")
            is JsonString -> CountRange.parse(v.value) ?: return Outcome.failure(DiagCode.SHARE_LINK_INVALID, "$at.interval — не «N» или «N-M»")
            else -> return Outcome.failure(DiagCode.SHARE_LINK_INVALID, "$at.interval — не того типа")
        }
        return Outcome.Success(Hysteria2Hop(modes, ports, interval?.takeUnless { it.from == 0 && it.to == 0 }))
    }

    /**
     * Скорость Brutal, как её читает Xray 26.9.30 (`infra/conf/transport_method.go`,
     * `Bandwidth.Bps`): число и единица `b`/`k`/`m`/`g`/`t` (по 1024, можно с
     * `b` или `bps`), — биты в секунду; ответ — байт в секунду. Не понять — null.
     */
    internal fun bandwidth(text: String): Long? {
        val s = text.trim().lowercase()
        if (s.isEmpty()) return 0
        val idx = s.indexOfFirst { (it < '0' || it > '9') && it != '.' }.let { if (it < 0) s.length else it }
        val value = s.substring(0, idx).toDoubleOrNull()?.takeIf { it.isFinite() && it >= 0 } ?: return null
        val mul = when (s.substring(idx).trim()) {
            "", "b", "bps" -> 1.0
            "k", "kb", "kbps" -> 1024.0
            "m", "mb", "mbps" -> 1024.0 * 1024
            "g", "gb", "gbps" -> 1024.0 * 1024 * 1024
            "t", "tb", "tbps" -> 1024.0 * 1024 * 1024 * 1024
            else -> return null
        }
        val bits = value * mul
        if (bits >= Long.MAX_VALUE.toDouble()) return null
        return bits.toLong() / 8
    }

    /** `fm` без содержания: пусто или `{}`. */
    private fun emptyFinalMask(text: String): Boolean = text.isBlank() || json(text)?.fields?.isEmpty() == true

    /**
     * Что внутри `fm` у ссылки VLESS или Trojan (D-107): finalmask Xray
     * бывает у любого транспорта — маски `tcp`, `udp` и `quicParams`; IR их
     * у этих протоколов не выражает. Журнал телефона 31.10.2026 говорил
     * только «неподдержанные параметры: fm» — теперь называются ключи и
     * типы масок, без значений: в масках бывают пароли.
     */
    private fun finalMaskNames(text: String): String {
        val root = json(text) ?: return "fm (не объект JSON)"
        val names = mutableListOf<String>()
        for ((key, value) in root.fields) {
            when {
                (key == "tcp" || key == "udp") && value is JsonArray && value.items.isNotEmpty() -> value.items.forEachIndexed { i, m ->
                    val type = ((m as? JsonObject)?.get("type") as? JsonString)?.value?.takeIf { MASK_TYPE.matches(it) }
                    names += if (type != null) "fm.$key[$i] (маска $type)" else "fm.$key[$i]"
                }
                key == "quicParams" && value is JsonObject && value.fields.isNotEmpty() -> value.fields.keys.forEach { names += "fm.quicParams.$it" }
                else -> names += "fm.$key"
            }
        }
        return names.sorted().joinToString()
    }

    /** Тип маски Xray в сообщении — только имя вида `header-custom`; прочее не цитируется. */
    private val MASK_TYPE = Regex("[a-z0-9-]{1,32}")

    /** Объект JSON из параметра ссылки; не JSON или не объект — null (без цитаты значения: в нём бывают секреты). */
    private fun json(text: String): JsonObject? = try {
        Json.parse(text, maxDepth = 8) as? JsonObject
    } catch (e: JsonParseException) {
        null
    }

    private fun profile(
        text: String,
        parts: Parts,
        endpoint: Endpoint,
        idPrefix: String,
        protocol: ProtocolSpec,
        transport: TransportSpec,
        security: SecuritySpec,
    ): ServerProfile {
        // Устойчивый id: от всего, кроме имени-фрагмента. Хеш — не секрет, но и не обратим.
        val id = "$idPrefix.${Checksums.sha256(text.substringBefore('#')).take(12)}"
        val name = parts.fragment?.takeIf { it.isNotBlank() && it.length <= 128 && com.dpsmpx.dppass.core.DisplayName.safe(it) }?.trim()
            ?: "${endpoint.host}:${endpoint.port}"
        return ServerProfile(ProfileId(id), name, endpoint, protocol, transport, security, CandidateHints())
    }

    private fun decodeBase64(s: String): String? {
        val compact = s.trim().trimEnd('=')
        if (compact.isEmpty()) return null
        val padded = compact + "=".repeat((4 - compact.length % 4) % 4)
        for (d in listOf(Base64.getDecoder(), Base64.getUrlDecoder())) {
            val bytes = runCatching { d.decode(padded) }.getOrNull() ?: continue
            val text = runCatching { Charsets.UTF_8.newDecoder().decode(java.nio.ByteBuffer.wrap(bytes)).toString() }.getOrNull() ?: continue
            if (text.none { it.code < 0x20 }) return text
        }
        return null
    }

    /**
     * Имя из `sni`/`host` — в том виде, в каком его дал бы документ
     * (нижний регистр, без точки в конце), чтобы один и тот же сервер
     * давал один и тот же IR. Пустое значение — то же, что отсутствие
     * параметра. Неверное имя остаётся как есть: его отвергает
     * `ConfigValidator.validateProfile` с путём, а не разбор ссылки молча.
     */
    private fun domainParam(value: String?): String? = value?.takeIf { it.isNotEmpty() }?.let { Host.normalizeDomain(it) ?: it }

    private fun unsupported(what: String): Outcome.Failure = Outcome.Failure(
        listOf(
            Diagnostic.error(DiagCode.SHARE_LINK_INVALID, "ссылка содержит то, что DPpass пока не выражает без потери смысла")
                .withCause(Diagnostic.warning(DiagCode.SHARE_LINK_PARAM_UNSUPPORTED, "неподдержанные параметры: ${safeNames(what)}")),
        ),
    )

    private fun safeNames(what: String): String = what.take(256).map { c ->
        if (c.isISOControl() || c in '\u202a'..'\u202e' || c in '\u2066'..'\u2069') '�' else c
    }.joinToString("")

    private class Parts(val user: String, val host: String, val port: String, val query: Map<String, String>, val fragment: String?)

    private fun split(rest: String): Parts? {
        val fragmentAt = rest.indexOf('#')
        val beforeFragment = if (fragmentAt >= 0) rest.substring(0, fragmentAt) else rest
        val fragment = if (fragmentAt >= 0) percentDecode(rest.substring(fragmentAt + 1)) else null
        val queryAt = beforeFragment.indexOf('?')
        val authority = (if (queryAt >= 0) beforeFragment.substring(0, queryAt) else beforeFragment).removeSuffix("/")
        val queryText = if (queryAt >= 0) beforeFragment.substring(queryAt + 1) else ""
        val at = authority.lastIndexOf('@')
        if (at <= 0) return null
        val user = percentDecode(authority.substring(0, at)) ?: return null
        val hostPort = authority.substring(at + 1)
        val (host, port) = if (hostPort.startsWith("[")) {
            val end = hostPort.indexOf(']')
            if (end < 0 || end + 2 > hostPort.length || hostPort[end + 1] != ':') return null
            hostPort.substring(0, end + 1) to hostPort.substring(end + 2)
        } else {
            val colon = hostPort.lastIndexOf(':')
            if (colon <= 0) return null
            hostPort.substring(0, colon) to hostPort.substring(colon + 1)
        }
        val query = LinkedHashMap<String, String>()
        if (queryText.isNotEmpty()) {
            for (pair in queryText.split('&')) {
                if (pair.isEmpty()) continue
                val k = percentDecode(pair.substringBefore('='))?.lowercase() ?: return null
                val v = percentDecode(pair.substringAfter('=', "")) ?: return null
                if (query.containsKey(k)) return null // повторный параметр — неоднозначность
                query[k] = v
            }
        }
        if (user.isEmpty() || host.isEmpty()) return null
        return Parts(user, host, port, query, fragment)
    }

    /** %XX → байты UTF-8; «+» остаётся «+» (это не форма HTML). */
    internal fun percentDecode(s: String): String? {
        if ('%' !in s) return s
        val out = java.io.ByteArrayOutputStream()
        var i = 0
        while (i < s.length) {
            val c = s[i]
            if (c == '%') {
                if (i + 2 >= s.length) return null
                val hex = s.substring(i + 1, i + 3)
                if (!hex.all { it.isDigit() || it.lowercaseChar() in 'a'..'f' }) return null
                out.write(hex.toInt(16))
                i += 3
            } else {
                val count = if (c.isHighSurrogate() && i + 1 < s.length && s[i + 1].isLowSurrogate()) 2 else 1
                out.write(s.substring(i, i + count).toByteArray(Charsets.UTF_8))
                i += count
            }
        }
        // String(bytes, charset), а не ByteArrayOutputStream.toString(Charset): второго нет на Android ниже API 33.
        return String(out.toByteArray(), Charsets.UTF_8)
    }

    private val SCHEME = Regex("""^([a-zA-Z][a-zA-Z0-9+.-]{1,15})://""")
}
