package com.dpsmpx.dppass.diagnostics

/**
 * Редактирование свободного текста перед журналом и отчётом.
 *
 * Работает **по умолчанию** для каждой строки журнала (D-11): лучше
 * вырезать лишнее, чем пропустить UUID или токен подписки. Секреты в
 * типизированном виде защищает [Secret]; редактор — вторая линия для
 * текста, который пришёл снаружи (сообщения ядра, URL, исключения).
 *
 * - [Level.STANDARD] — UUID, ссылки (остаются схема, хост и порт),
 *   пары `ключ=значение` с секретными именами, длинные токены;
 * - [Level.STRICT] — ещё и IP-адреса и имена хостов в ссылках: для
 *   отчёта, который пользователь отправляет кому-то.
 */
class Redactor(private val level: Level = Level.STANDARD) {
    enum class Level { STANDARD, STRICT }

    fun redact(text: String): String {
        var out = text
        out = URL.replace(out) { m -> redactUrl(m) }
        out = UUID.replace(out, UUID_MARK)
        out = SECRET_PAIR.replace(out) { m -> m.groupValues[1] + m.groupValues[2] + TOKEN_MARK }
        // Длинная последовательность — токен, только если в ней есть и буквы,
        // и цифры: так не страдают коды диагностики вроде ACTIVATION_REJECTED.
        out = LONG_TOKEN.replace(out) { m ->
            if (m.value.any(Char::isDigit) && m.value.any(Char::isLetter)) TOKEN_MARK else m.value
        }
        if (level == Level.STRICT) {
            out = IPV4.replace(out, IP_MARK)
            out = IPV6.replace(out) { m -> redactIpv6(m.value) }
        }
        return out
    }

    /**
     * Кандидат в IPv6. Одиночное двоеточие с края — не часть адреса:
     * адрес IPv6 начинается и кончается группой или `::`. Без этого порт
     * в ошибке Go `dial tcp <ip>:443: connect` уходил под метку целиком
     * (`<ip><ip>`). Остаток с двумя двоеточиями и больше — по-прежнему
     * адрес: адрес не пропускается, теряется только лишняя метка.
     */
    private fun redactIpv6(value: String): String {
        val start = if (value.startsWith(":") && !value.startsWith("::")) 1 else 0
        val end = if (value.length > start && value.endsWith(":") && !value.endsWith("::")) value.length - 1 else value.length
        if (end <= start || value.substring(start, end).count { it == ':' } < 2) return value
        return value.substring(0, start) + IP_MARK + value.substring(end)
    }

    private fun redactUrl(m: MatchResult): String {
        val scheme = m.groupValues[1]
        val hostPort = m.groupValues[3]
        val rest = m.groupValues[4]
        val host = if (level == Level.STRICT) HOST_MARK else hostPort
        val tail = if (rest.isEmpty()) "" else "/$TOKEN_MARK"
        val user = if (m.groupValues[2].isEmpty()) "" else "$TOKEN_MARK@"
        return "$scheme://$user$host$tail"
    }

    companion object {
        const val UUID_MARK: String = "<uuid>"
        const val TOKEN_MARK: String = "<redacted>"
        const val IP_MARK: String = "<ip>"
        const val HOST_MARK: String = "<host>"

        private val UUID = Regex("""\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b""")

        // схема://[userinfo@]хост[:порт][остаток до пробела или кавычки]
        private val URL = Regex(
            """\b([a-zA-Z][a-zA-Z0-9+.-]{1,15})://(?:([^\s/@"'<>]*)@)?(\[[0-9a-fA-F:.]+]|[^\s/?#:"'<>@]+(?::\d{1,5})?)([^\s"'<>]*)""",
        )

        private val SECRET_PAIR = Regex(
            """(?i)\b(password|passwd|pwd|pass|token|secret|private_?key|public_?key|psk|pbk|sid|short_?id|uuid|auth|obfs-password)(\s*[=:]\s*)(?!<redacted>)[^\s&,;"'<>]+""",
        )

        // base64/base64url/hex длиной от 24 символов: ключи, токены, хеши подписок.
        private val LONG_TOKEN = Regex("""(?<![A-Za-z0-9+/_=-])[A-Za-z0-9+/_=-]{24,}(?![A-Za-z0-9+/_=-])""")

        private val IPV4 = Regex("""\b(?:\d{1,3}\.){3}\d{1,3}\b""")
        private val IPV6 = Regex("""(?<![0-9a-fA-F:])(?:[0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}(?![0-9a-fA-F:])""")
    }
}
