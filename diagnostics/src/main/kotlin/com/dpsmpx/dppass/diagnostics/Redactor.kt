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
 * - [Level.STRICT] — ещё и IP-адреса и имена хостов, в ссылках и в
 *   тексте: для отчёта, который пользователь отправляет кому-то.
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
            out = HOSTNAME.replace(out, HOST_MARK)
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

        // Имя хоста вне ссылки — в ошибках Go и Xray: «lookup <имя>: no such
        // host», «x509: … wanted to match <имя>», «not <имя>», «tcp:<имя>:443».
        // Журнал 19 октября 2026: так имя сервера ушло в скопированный журнал.
        // Только строчные: имена типов (`java.lang.IllegalStateException`) и
        // кадры стека остаются. Сразу после точки, «/» или «-» имя не
        // начинается: это середина пути или имени файла.
        // Последняя метка — буквы или IDN (`xn--p1ai`), иначе это версия
        // (`0.7.25-dev`) или идентификатор профиля (`s1.7ed027eec175`).
        // `udp` и `tcp` — не домены верхнего уровня, а ключи finalmask в
        // сообщениях о ссылках (`fm.udp[0] (маска noise)`, D-107): журнал
        // 31.10.2026 без этого назвал бы их `<host>`.
        private val HOSTNAME = Regex(
            """(?<![\w./-])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?!(?:udp|tcp)(?![\w-]|\.\w))(?:[a-z]{2,63}|xn--[a-z0-9-]{1,59})(?![\w-]|\.\w)""",
        )
    }
}
