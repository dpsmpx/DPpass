package com.dpsmpx.dppass.connection

import java.util.Locale

/**
 * A deliberately small, safe domain allowlist for the rooted nfqws2 backend.
 * Empty list means all supported traffic, not an unconfigured/failed parser.
 * Only ASCII DNS names are accepted. IDNs must be supplied in punycode.
 * No filesystem paths, flags, shell input or remote URLs are accepted.
 */
data class Zapret2Hostlist(val domains: List<String>) {
    val isEmpty: Boolean get() = domains.isEmpty()
    fun format(): String = domains.joinToString("\n")

    companion object {
        /** Редактируемый набор суффиксов, не полный перечень CDN: по умолчанию список пуст. */
        val YOUTUBE_CDN_PRESET: String = listOf(
            "youtube.com", "youtu.be", "youtube-nocookie.com",
            "youtubei.googleapis.com", "googlevideo.com", "ytimg.com", "ggpht.com",
        ).joinToString("\n")

        private const val MAX_TEXT = 65_536
        private const val MAX_DOMAINS = 2_048
        private val labelPattern = Regex("[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")

        fun parse(text: String): Result<Zapret2Hostlist> = runCatching {
            require(text.length <= MAX_TEXT) { "Список Zapret2 превышает 64 КиБ" }
            val unique = LinkedHashSet<String>()
            text.lineSequence().forEachIndexed { index, line ->
                val entry = line.trim().lowercase(Locale.ROOT)
                if (entry.isNotEmpty() && !entry.startsWith("#")) {
                    require(entry.length <= 253 && entry.contains('.')) {
                        "Строка ${index + 1}: нужен домен, например example.org"
                    }
                    val labels = entry.split('.')
                    require(labels.all { labelPattern.matches(it) } && labels.last().any { it in 'a'..'z' }) {
                        "Строка ${index + 1}: неверное имя домена"
                    }
                    unique += entry
                    require(unique.size <= MAX_DOMAINS) { "Допустимо не более 2048 доменов" }
                }
            }
            Zapret2Hostlist(unique.toList())
        }
    }
}

/** Strategies supported by the local, no-root TCP dialer; not upstream Lua. */
enum class Zapret2VpnStrategy(val wire: String) {
    FAKE_TTL_3("fake-3"),
    FAKE_TTL_5("fake-5"),
    DISORDER("disorder"),
    SPLIT_SNI("split"),
    SPLIT_FIRST("split-1");

    companion object {
        fun of(value: String?): Zapret2VpnStrategy =
            entries.firstOrNull { it.wire == value } ?: FAKE_TTL_3
    }
}
