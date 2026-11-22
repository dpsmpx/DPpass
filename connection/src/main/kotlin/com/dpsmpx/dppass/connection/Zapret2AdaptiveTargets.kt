package com.dpsmpx.dppass.connection

import java.util.Locale

/**
 * Explicitly selected destinations from the Connections screen. No passive
 * history is persisted; automatic learning of other destinations is memory-
 * only and reset when the VPN reconnects. Domain selection also covers
 * subdomains at a DNS-label boundary in the native adapter.
 */
object Zapret2AdaptiveTargets {
    const val MAX_TARGETS = 512

    fun normalize(raw: String): String? {
        val text = raw.trim().lowercase(Locale.ROOT).removeSuffix(".")
        if (text.isEmpty() || text.length > 253 || text.any { it.isWhitespace() }) return null
        val chunks = text.split('.')
        if (chunks.size == 4 && chunks.all { it.isNotEmpty() && it.all(Char::isDigit) }) {
            if (chunks.all { it.length <= 3 && (it.toIntOrNull() ?: 256) in 0..255 }) return text
            return null
        }
        return Zapret2Hostlist.parse(text).getOrNull()?.domains?.singleOrNull()
    }

    fun parse(text: String): Result<List<String>> = runCatching {
        require(text.length <= 65_536) { "Список адресов слишком длинный" }
        val unique = LinkedHashSet<String>()
        text.lineSequence().filter { it.isNotBlank() }.forEach { line ->
            val host = normalize(line)
            require(host != null) { "Неверное имя или адрес" }
            unique += host
            require(unique.size <= MAX_TARGETS) { "Выбрано слишком много адресов" }
        }
        unique.toList()
    }

    fun update(existing: String, host: String, enabled: Boolean): Result<String> = runCatching {
        val key = requireNotNull(normalize(host)) { "Выберите соединение с доменом или IPv4" }
        val all = parse(existing).getOrThrow().toMutableList()
        all.remove(key)
        if (enabled) {
            require(all.size < MAX_TARGETS) { "Лимит выбранных адресов" }
            all.add(key)
        }
        all.joinToString("\n")
    }
}
