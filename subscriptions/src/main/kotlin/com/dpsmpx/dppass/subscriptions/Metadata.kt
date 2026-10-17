package com.dpsmpx.dppass.subscriptions

import com.dpsmpx.dppass.diagnostics.DiagCode
import com.dpsmpx.dppass.diagnostics.Diagnostic
import java.util.Base64

/**
 * Метаданные подписки из заголовков ответа и строк `#ключ: значение`
 * в теле.
 *
 * Применяются только **информационные** поля (название, трафик,
 * интервал обновления, ссылки поддержки). Директивы, которыми поставщик
 * управляет клиентом (сменить адрес подписки, спрятать настройки,
 * включить или выключить маршрутизацию, поменять DNS, списки
 * приложений, TUN, mux, фрагментацию…), **не применяются**: каждая
 * найденная отмечается предупреждением SUBSCRIPTION_DIRECTIVE_IGNORED
 * (D-11, `docs/SECURITY_MODEL.md`, угроза T2). Значения директив в
 * сообщения не попадают — в них бывают адреса и токены.
 */
object MetadataParser {
    private val SAFE = setOf(
        "profile-title", "profile-update-interval", "subscription-userinfo",
        "support-url", "profile-web-page-url", "announce",
    )

    /** Признаки управляющих директив поставщика (названия публично описаны в экосистеме). */
    private val CONTROL_PREFIXES = listOf(
        "new-", "fallback-", "hide-", "routing", "per-app-", "tun-", "xray-tun", "dns-", "mux-", "noises-",
        "fragmentation-", "custom-", "sniffing-", "subscription-", "subscriptions-", "change-user-agent",
        "proxy-", "inbound-", "http-auth", "socks-auth", "ping-", "exclude-", "include-", "server-address-",
        "app-auto-start", "block-", "providerid", "provider-id", "hwid", "no-limit", "color-profile", "dont-use-filter",
        "manual-block-", "notification-", "check-url-",
    )

    data class Result(val metadata: SubscriptionMetadata, val notes: List<Diagnostic>)

    fun parse(headers: Map<String, String>, bodyDirectives: Map<String, String>): Result {
        val notes = mutableListOf<Diagnostic>()
        val values = LinkedHashMap<String, String>()
        val ignored = sortedSetOf<String>()
        // Пустое значение — «не задано», а не неверное значение и не директива: панели
        // (Remnawave) шлют незаполненные поля пустыми заголовками.
        for ((rawKey, value) in headers) {
            if (value.isBlank()) continue
            val key = rawKey.lowercase()
            when {
                key in SAFE -> values[key] = value
                isControl(key) -> ignored += key
            }
        }
        // В теле поставщик может передать то же, что в заголовках; тело не перекрывает заголовок.
        for ((rawKey, value) in bodyDirectives) {
            if (value.isBlank()) continue
            val key = rawKey.lowercase()
            if (key in SAFE) values.putIfAbsent(key, value) else ignored += key
        }
        if (ignored.isNotEmpty()) {
            notes += Diagnostic.warning(
                DiagCode.SUBSCRIPTION_DIRECTIVE_IGNORED,
                "директивы поставщика не применены (меняют поведение клиента без согласия пользователя): ${ignored.joinToString()}",
            )
        }
        fun bad(key: String, why: String) {
            notes += Diagnostic.warning(DiagCode.SUBSCRIPTION_METADATA_INVALID, "$key: $why")
        }

        val title = values["profile-title"]?.let(::decodeText)?.trim()?.takeIf { it.isNotEmpty() }?.let {
            // Правило имени то же, что у SubscriptionService (управляющие — и DEL, и C1):
            // название видно в списке, уведомлении и журнале.
            if (it.length > 64 || it.any { c -> c.isISOControl() }) {
                null.also { bad("profile-title", "длиннее 64 символов или с управляющими символами") }
            } else {
                it
            }
        }
        val interval = values["profile-update-interval"]?.trim()?.let { v ->
            v.toIntOrNull()?.takeIf { it in 1..24 * 30 } ?: null.also { bad("profile-update-interval", "ожидались часы 1..720") }
        }
        val traffic = values["subscription-userinfo"]?.let { v ->
            parseUserInfo(v) ?: null.also { bad("subscription-userinfo", "неверный формат") }
        }
        fun httpsUrl(key: String): String? = values[key]?.trim()?.let { u ->
            if (u.startsWith("https://") && u.length <= 512 && u.none { it.isWhitespace() }) u else null.also { bad(key, "принимаются только ссылки https://") }
        }
        val announce = values["announce"]?.let(::decodeText)?.trim()?.takeIf { it.isNotEmpty() }?.let {
            if (it.length > 200) it.take(200).also { bad("announce", "обрезано до 200 символов") } else it
        }
        return Result(SubscriptionMetadata(title, interval, traffic, httpsUrl("support-url"), httpsUrl("profile-web-page-url"), announce), notes)
    }

    private fun isControl(key: String): Boolean = CONTROL_PREFIXES.any { key.startsWith(it) }

    /** Текст или `base64:…` (так передают не-ASCII в заголовках). */
    private fun decodeText(v: String): String? {
        val t = v.trim()
        if (!t.startsWith("base64:")) return t
        return runCatching { String(Base64.getDecoder().decode(t.removePrefix("base64:")), Charsets.UTF_8) }.getOrNull()
    }

    internal fun parseUserInfo(v: String): TrafficInfo? {
        val parts = v.split(';').map { it.trim() }.filter { it.isNotEmpty() }
        if (parts.isEmpty()) return null
        val m = HashMap<String, Long>()
        for (p in parts) {
            val k = p.substringBefore('=').trim().lowercase()
            val n = p.substringAfter('=', "").trim().toLongOrNull() ?: return null
            if (n < 0 || k !in setOf("upload", "download", "total", "expire")) return null
            m[k] = n
        }
        return TrafficInfo(m["upload"], m["download"], m["total"], m["expire"]?.takeIf { it > 0 })
    }
}
