package com.dpsmpx.dppass.engine.xray

/**
 * Fixed public YouTube service-path controls. Nothing here grants automatic
 * cross-domain AUTO pinning or claims real media playback. No domain tokens,
 * raw IPs, credentials, response contents or certificates are exported.
 */
object Zapret2YoutubePathReport {
    val services = listOf("home", "api", "thumb")
    val protocols = listOf("h1", "h2")
    val methods = listOf("plain", "tlsrec-split", "fake-5")
    const val REPEATS = 2
    fun preparation(service: String): String {
        require(service in services)
        return "yt_path_prepare_" + service
    }
    fun trial(service: String, protocol: String): String {
        require(service in services && protocol in protocols)
        return "yt_path_" + service + "_" + protocol
    }
    fun verified(row: Zapret2GoogleAttempt): Boolean {
        val service = services.firstOrNull {
            row.target.startsWith("yt_path_" + it + "_")
        } ?: return false
        val protocol = protocols.firstOrNull {
            row.target == trial(service, it)
        } ?: return false
        val expectedAlpn = if (protocol == "h2") "h2" else "http/1.1"
        if (row.result.protocol != protocol || row.result.alpn != expectedAlpn ||
            row.result.tlsStage != "tls_verified") return false
        return if (service == "api") {
            row.result.outcome == "http_reachable" &&
                row.result.httpStatus in 200..499
        } else {
            row.result.outcome == "ok" &&
                row.result.httpStatus in 200..299 && row.result.bodyBytes >= 128
        }
    }

    fun render(network: String, preparations: List<Zapret2GoogleAttempt>,
        samples: List<Zapret2GoogleAttempt>): String = buildString {
        appendLine("=== DPpass — контроль путей YouTube HTTPS/API/CDN ===")
        appendLine("Сеть: $network")
        appendLine("Цели: www.youtube.com GET /, youtubei.googleapis.com anonymous POST /youtubei/v1/browse,")
        appendLine("i.ytimg.com fixed public JPEG thumbnail.")
        appendLine("DNS: только проверенный Google DoH через защищённый Xray, публичный IPv4.")
        appendLine("Все проверки без cookies, идентификаторов, ключей и приватных URL.")
        for (service in services) {
            val prepared = preparations.singleOrNull {
                it.target == preparation(service)
            }?.result
            appendLine("service=$service dns=${prepared?.outcome ?: "missing"}" +
                " ipv4=${prepared?.dnsAnswers ?: 0}" +
                " fingerprint=${prepared?.dnsFingerprint ?: "-"}")
            for (proto in protocols) {
                for (method in methods) {
                    val matching = samples.filter { it.target == trial(service, proto) &&
                        it.strategy == method }
                    val good = matching.count(::verified)
                    appendLine("  $proto $method: $good/${matching.size} " +
                        "tls_verified_http_or_content")
                    for (row in matching) {
                        val r = row.result
                        appendLine("    attempt=${row.attempt} outcome=${r.outcome}" +
                            " stage=${r.tlsStage} alpn=${r.alpn}" +
                            " http=${r.httpStatus} bounded_bytes=${r.bodyBytes}" +
                            " elapsed_ms=${r.elapsedMillis}")
                    }
                }
            }
        }
        appendLine("API 2xx/4xx доказывает только TLS+HTTP, а не загрузку ленты.")
        appendLine("JPEG миниатюра доказывает лишь доступность статического CDN, не видеопотока.")
        appendLine("googlevideo CDN и воспроизведение реального видео НЕ проверялись.")
        appendLine("Этот тест не изменяет AUTO, маршруты VPN, системный DNS или веса нейросети.")
    }
}
