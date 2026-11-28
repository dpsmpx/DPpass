package com.dpsmpx.dppass.app

import com.dpsmpx.dppass.engine.Zapret2ProbeCatalog
import com.dpsmpx.dppass.engine.xray.DptsPlan
import com.dpsmpx.dppass.engine.xray.DptsScript

/** Generate ordinary DPTS/1 text; the normal compiler remains authoritative. */
internal object DptsBuilder {
    enum class Mode(val label: String, val statement: String, val maxIps: Int) {
        HTTPS_H1("HTTPS · HTTP/1.1", "https protocols=h1", 8),
        HTTPS_H2("HTTPS · HTTP/2", "https protocols=h2", 8),
        HTTPS_BOTH("HTTPS · H1 + H2", "https protocols=h1,h2", 8),
        TLS12("TLS 1.2", "tls versions=12", 2),
        TLS13("TLS 1.3", "tls versions=13", 2),
        TLS_BOTH("TLS 1.2 + 1.3", "tls versions=12,13", 2),
        QUIC("QUIC · HTTP/3 handshake", "quic", 8);

        val https: Boolean get() = name.startsWith("HTTPS_")
        fun methods(): List<String> = if (this == QUIC)
            Zapret2ProbeCatalog.scriptQuicMethods.toList()
        else Zapret2ProbeCatalog.scriptTcpMethods.toList()
    }

    data class Draft(val source: String, val plan: DptsPlan)

    fun create(title: String, host: String, mode: Mode, methods: Set<String>,
        ips: Int, attempts: Int, timeoutMs: Int, observe: Boolean): Draft {
        require(title.isNotBlank() && title.length <= 80 &&
            title.none { it == '"' || it.isISOControl() || it.category in setOf(
                CharCategory.FORMAT, CharCategory.LINE_SEPARATOR, CharCategory.PARAGRAPH_SEPARATOR) }) {
            "Invalid title"
        }
        require(host.isNotBlank() && host.none { it.isWhitespace() || it.isISOControl() }) { "Invalid host" }
        require(methods.isNotEmpty() && mode.methods().containsAll(methods)) { "Select at least one supported method" }
        require(ips in 1..mode.maxIps && attempts in 1..3 && timeoutMs in 1000..12000) { "Invalid matrix dimensions" }
        require(!observe || mode.https) { "Learning observations require HTTPS" }
        val source = buildString {
            appendLine(DptsScript.HEADER)
            appendLine("name \"$title\"")
            appendLine("host $host")
            appendLine("learn " + if (observe) "observe" else "off")
            appendLine(mode.statement + " methods=" + mode.methods().filter { it in methods }.joinToString(",") +
                " ips=$ips attempts=$attempts timeout_ms=$timeoutMs")
        }
        return Draft(source, DptsScript.compile(source))
    }
}
