package com.dpsmpx.dppass.connection

import com.dpsmpx.dppass.core.Json
import com.dpsmpx.dppass.core.JsonArray
import com.dpsmpx.dppass.core.JsonObject
import com.dpsmpx.dppass.core.JsonParseException
import com.dpsmpx.dppass.core.JsonString
import com.dpsmpx.dppass.diagnostics.DiagCode
import com.dpsmpx.dppass.diagnostics.Outcome
import com.dpsmpx.dppass.routing.SiteEntry
import com.dpsmpx.dppass.routing.SiteList
import com.dpsmpx.dppass.routing.SiteListKind
import com.dpsmpx.dppass.routing.SiteLists
import java.util.Base64

/** Что из профиля не взято и почему (D-93): поле (и номер записи) — и причина. */
data class HappSkip(val field: String, val reason: String)

/**
 * Профиль маршрутизации Happ, разобранный для своих списков (D-93):
 * [lists] — что добавится, [skipped] — что не будет взято, с причиной.
 * Ничего не применяется без согласия пользователя (T13).
 */
data class HappRoutingImport(val name: String?, val lists: SiteLists, val skipped: List<HappSkip>) {
    val total: Int get() = SiteListKind.entries.sumOf { lists[it].size }
}

/**
 * Импорт публично описанного профиля маршрутизации Happ (D-93;
 * `docs/research/HAPP_SOURCE_AUDIT.md`, §7, 25.10.2026): JSON со списками
 * сайтов и адресов «напрямую / через прокси / блокировать» — сам или
 * ссылкой `happ://routing/add|onadd/{base64}`. Берутся только списки — в
 * свои списки DPpass; DNS, адреса геоданных, подмена имён и прочее — нет,
 * каждое с причиной. Зашифрованные ссылки (`happ://crypt…`) не
 * открываются: они прячут конфигурацию от пользователя (D-11).
 */
object HappRouting {
    private const val ROUTING = "happ://routing/"

    /** Поле профиля → свой список; имена — как в описании формата, без учёта регистра. */
    private val LIST_FIELDS: Map<String, SiteListKind> = mapOf(
        "directsites" to SiteListKind.DIRECT,
        "directip" to SiteListKind.DIRECT,
        "proxysites" to SiteListKind.PROXY,
        "proxyip" to SiteListKind.PROXY,
        "blocksites" to SiteListKind.BLOCK,
        "blockip" to SiteListKind.BLOCK,
    )

    /** Поля, которые не берутся, — с причиной; ключ — имя поля в нижнем регистре. */
    private val SKIPPED_FIELDS: Map<String, String> = mapOf(
        "globalproxy" to "что не в списках — через туннель; так в DPpass всегда, «всё напрямую» профилем не включается",
        "remotednstype" to "DNS выбирается в настройках DPpass: DoH через туннель (D-38)",
        "remotednsdomain" to "DNS выбирается в настройках DPpass: DoH через туннель (D-38)",
        "remotednsip" to "DNS выбирается в настройках DPpass: DoH через туннель (D-38)",
        "domesticdnstype" to "имена сайтов «напрямую» резолвит система, как у остальных прямых соединений (D-38)",
        "domesticdnsdomain" to "имена сайтов «напрямую» резолвит система, как у остальных прямых соединений (D-38)",
        "domesticdnsip" to "имена сайтов «напрямую» резолвит система, как у остальных прямых соединений (D-38)",
        "geoipurl" to "геоданные — набор в самом DPpass (D-27); загрузки с адреса из профиля нет",
        "geositeurl" to "геоданные — набор в самом DPpass (D-27); загрузки с адреса из профиля нет",
        "dnshosts" to "подмены адресов имён нет: имя резолвит выбранный DNS",
        "domainstrategy" to "у DPpass своё правило: решение по имени, затем по адресу, если имя не совпало",
        "fakedns" to "подмены адресов имён нет",
        "routeorder" to "порядок у DPpass постоянный: блокировать, через туннель, напрямую",
        "usechunkfiles" to "геоданные DPpass не режутся на части",
        "lastupdated" to "дата профиля не нужна: списки меняются только вручную",
        "name" to "",
    )

    /** Похоже ли на профиль Happ: ссылка `happ://routing/…` или JSON с его списками. */
    fun looksLike(text: String): Boolean {
        val t = text.trim()
        if (t.startsWith(ROUTING, ignoreCase = true)) return true
        if (!t.startsWith("{")) return false
        val lower = t.lowercase()
        return LIST_FIELDS.keys.any { "\"$it\"" in lower }
    }

    /** Зашифрованная ссылка Happ: её не открыть, не обходя чужую защиту (`HAPP_SOURCE_AUDIT.md`, §4). */
    fun isEncrypted(text: String): Boolean = text.trim().startsWith("happ://crypt", ignoreCase = true)

    /**
     * Ссылка или JSON → что добавится и что нет. [geoProblem] — запись
     * geosite/geoip, кода которой нет в наборе ядра (null — код есть).
     */
    fun parse(text: String, geoProblem: (SiteEntry) -> String? = { null }): Outcome<HappRoutingImport> {
        val t = text.trim()
        val json = if (t.startsWith(ROUTING, ignoreCase = true)) {
            val rest = t.substring(ROUTING.length)
            val action = rest.substringBefore('/')
            when (action.lowercase()) {
                "add", "onadd" -> decode(rest.substringAfter('/', "")) ?: return Outcome.failure(
                    DiagCode.SUBSCRIPTION_FORMAT_UNKNOWN,
                    "ссылка профиля Happ: после happ://routing/$action/ — не base64 с JSON",
                )
                "off" -> return Outcome.failure(
                    DiagCode.CAPABILITY_FEATURE_UNSUPPORTED,
                    "happ://routing/off выключает маршрутизацию ссылкой — в DPpass её меняет только пользователь в настройках (D-11)",
                )
                else -> return Outcome.failure(DiagCode.SUBSCRIPTION_FORMAT_UNKNOWN, "ссылка профиля Happ: неизвестное действие «${action.take(16)}»")
            }
        } else {
            t
        }
        val root = try {
            Json.parse(json) as? JsonObject
        } catch (e: JsonParseException) {
            null
        } ?: return Outcome.failure(DiagCode.SUBSCRIPTION_FORMAT_UNKNOWN, "профиль Happ — не объект JSON")
        val skipped = mutableListOf<HappSkip>()
        val entries = SiteListKind.entries.associateWith { LinkedHashMap<String, SiteEntry>() }
        var name: String? = null
        for ((key, value) in root.fields) {
            val k = key.lowercase()
            val kind = LIST_FIELDS[k]
            when {
                k == "name" -> name = (value as? JsonString)?.value?.trim()?.take(NAME_MAX)?.takeIf { it.isNotEmpty() && it.none(Char::isISOControl) }
                kind != null -> {
                    val items = (value as? JsonArray)?.items
                    if (items == null) {
                        skipped += HappSkip(key, "не список строк")
                        continue
                    }
                    for ((i, item) in items.withIndex()) {
                        val raw = (item as? JsonString)?.value
                        if (raw == null) {
                            skipped += HappSkip("$key[$i]", "не строка")
                            continue
                        }
                        when (val e = SiteEntry.parse(raw)) {
                            is Outcome.Failure -> skipped += HappSkip("$key[$i] «${raw.trim().take(ENTRY_SHOWN)}»", e.errors.first().message)
                            is Outcome.Success -> {
                                val geo = geoProblem(e.value)
                                if (geo != null) {
                                    skipped += HappSkip("$key[$i] «${e.value.text}»", geo)
                                } else {
                                    entries.getValue(kind).putIfAbsent(e.value.text, e.value)
                                }
                            }
                        }
                    }
                }
                k in SKIPPED_FIELDS -> SKIPPED_FIELDS.getValue(k).takeIf { it.isNotEmpty() && !isEmptyValue(value) }?.let { skipped += HappSkip(key, it) }
                else -> skipped += HappSkip(key.take(ENTRY_SHOWN), "неизвестное поле: DPpass не знает, что оно значит, и не угадывает (D-05)")
            }
        }
        // Запись в двух списках профиля — берётся из более осторожного (порядок своих списков).
        val seen = HashSet<String>()
        var lists = SiteLists.NONE
        for (kind in SiteLists.ORDER) {
            val kept = entries.getValue(kind).values.filter { e ->
                if (seen.add(e.text)) {
                    true
                } else {
                    skipped += HappSkip("${kind.wire} «${e.text}»", "уже в более строгом списке профиля")
                    false
                }
            }
            if (kept.size > SiteList.MAX_ENTRIES) {
                return Outcome.failure(DiagCode.LIMIT_EXCEEDED, "в списке «${kind.wire}» профиля ${kept.size} записей, предел — ${SiteList.MAX_ENTRIES}")
            }
            lists = lists.with(kind, SiteList(kept))
        }
        val result = HappRoutingImport(name, lists, skipped)
        if (result.total == 0) {
            val example = skipped.firstOrNull()?.let { " (например, ${it.field}: ${it.reason})" }.orEmpty()
            return Outcome.failure(DiagCode.SUBSCRIPTION_NO_USABLE_SERVERS, "в профиле Happ нет записей, которые DPpass взял бы в свои списки$example")
        }
        return Outcome.Success(result)
    }

    /** Пустое значение («», [], {}, "false") — не настройка, о нём молчать. */
    private fun isEmptyValue(v: com.dpsmpx.dppass.core.JsonValue): Boolean = when (v) {
        is JsonString -> v.value.isBlank() || v.value.equals("false", ignoreCase = true)
        is JsonArray -> v.items.isEmpty()
        is JsonObject -> v.fields.isEmpty()
        else -> false
    }

    /** base64 (обычный или для адресов, с отступом или без) → текст UTF-8; не вышло — null. */
    private fun decode(b64: String): String? {
        val compact = b64.trim().filterNot { it.isWhitespace() }
        if (compact.isEmpty() || compact.length > MAX_LINK) return null
        val padded = compact + "=".repeat((4 - compact.length % 4) % 4)
        for (d in listOf(Base64.getDecoder(), Base64.getUrlDecoder())) {
            val bytes = runCatching { d.decode(padded) }.getOrNull() ?: continue
            return String(bytes, Charsets.UTF_8)
        }
        return null
    }

    private const val NAME_MAX = 64
    private const val ENTRY_SHOWN = 64

    /** Ссылка длиннее — уже не профиль, а что-то другое (предел импорта — 1 МБ). */
    private const val MAX_LINK = ImportClassifier.MAX_BYTES
}
