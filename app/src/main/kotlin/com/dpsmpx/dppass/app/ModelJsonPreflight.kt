package com.dpsmpx.dppass.app

/** Strict, bounded structural preflight for the two local model formats.
 * JSONObject remains responsible for schema and dimensional validation.
 * No network or Android dependency; no input is included in error messages.
 */
internal object ModelJsonPreflight {
    private val fields = setOf(
        "format", "parameters", "seed", "hidden", "bias", "deep_hidden", "deep_bias",
        "output", "output_bias", "context_bias", "context_observations",
        "verified_html_bias", "verified_html_observations", "sparse", "sparse_recency", "observations",
    )

    fun accepts(raw: ByteArray, maxBytes: Int): Boolean {
        if (raw.isEmpty() || raw.size > maxBytes) return false
        return runCatching {
            Parser(raw.decodeToString(throwOnInvalidSequence = true)).check()
        }.getOrDefault(false)
    }

    private class Parser(private val source: String) {
        private var p = 0
        private fun peek(): Char = source.getOrElse(p) { '\u0000' }
        private fun take(c: Char): Boolean {
            if (p >= source.length || source[p] != c) return false
            p++
            return true
        }
        private fun expect(c: Char) { require(take(c)) }
        private fun space() {
            while (p < source.length && source[p] in " \t\r\n") p++
        }

        fun check(): Boolean {
            space()
            require(peek() == '{')
            value(0)
            space()
            return p == source.length
        }

        private fun value(depth: Int) {
            require(depth <= 4)
            space()
            when (peek()) {
                '{' -> obj(depth)
                '[' -> array(depth)
                '"' -> string()
                't' -> literal("true")
                'f' -> literal("false")
                'n' -> { require(depth == 1); literal("null") }
                '-', in '0'..'9' -> number()
                else -> error("invalid model JSON")
            }
        }

        private fun obj(depth: Int) {
            expect('{')
            space()
            if (take('}')) return
            val seen = HashSet<String>()
            while (true) {
                space()
                val key = string()
                require(seen.add(key))
                require(depth != 0 || key in fields)
                space()
                expect(':')
                value(depth + 1)
                space()
                if (take('}')) return
                expect(',')
            }
        }

        private fun array(depth: Int) {
            expect('[')
            space()
            if (take(']')) return
            while (true) {
                value(depth + 1)
                space()
                if (take(']')) return
                expect(',')
            }
        }

        private fun literal(text: String) {
            require(source.startsWith(text, p))
            p += text.length
        }

        private fun number() {
            take('-')
            if (!take('0')) {
                require(peek() in '1'..'9')
                while (peek() in '0'..'9') p++
            }
            if (take('.')) {
                require(peek() in '0'..'9')
                while (peek() in '0'..'9') p++
            }
            if (take('e') || take('E')) {
                if (!take('+')) take('-')
                require(peek() in '0'..'9')
                while (peek() in '0'..'9') p++
            }
        }

        private fun string(): String {
            expect('"')
            val result = StringBuilder()
            while (p < source.length) {
                val c = source[p++]
                if (c == '"') return result.toString()
                require(c >= ' ')
                if (c != '\\') {
                    result.append(c)
                    continue
                }
                require(p < source.length)
                when (val escaped = source[p++]) {
                    '"', '\\', '/' -> result.append(escaped)
                    'b' -> result.append('\b')
                    'f' -> result.append('\u000c')
                    'n' -> result.append('\n')
                    'r' -> result.append('\r')
                    't' -> result.append('\t')
                    'u' -> {
                        require(source.length - p >= 4)
                        var n = 0
                        repeat(4) {
                            val digit = when (val h = source[p++]) {
                                in '0'..'9' -> h - '0'
                                in 'a'..'f' -> h - 'a' + 10
                                in 'A'..'F' -> h - 'A' + 10
                                else -> error("invalid model JSON escape")
                            }
                            n = n * 16 + digit
                        }
                        result.append(n.toChar())
                    }
                    else -> error("invalid model JSON escape")
                }
            }
            error("unterminated model JSON string")
        }
    }
}
