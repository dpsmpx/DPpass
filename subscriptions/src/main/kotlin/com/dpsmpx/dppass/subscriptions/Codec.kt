package com.dpsmpx.dppass.subscriptions

import com.dpsmpx.dppass.core.Ids
import com.dpsmpx.dppass.core.Json
import com.dpsmpx.dppass.core.JsonArray
import com.dpsmpx.dppass.core.JsonNumber
import com.dpsmpx.dppass.core.JsonObject
import com.dpsmpx.dppass.core.JsonParseException
import com.dpsmpx.dppass.core.JsonString
import com.dpsmpx.dppass.core.JsonValue
import com.dpsmpx.dppass.core.SubscriptionId
import com.dpsmpx.dppass.diagnostics.DiagCode
import com.dpsmpx.dppass.diagnostics.Diagnostic
import com.dpsmpx.dppass.diagnostics.Outcome
import com.dpsmpx.dppass.diagnostics.Secret

/** Сохранённые подписки и какая из них сейчас применена (D-36). */
data class SubscriptionsState(val items: List<Subscription>, val activeId: SubscriptionId?) {
    fun find(id: SubscriptionId): Subscription? = items.firstOrNull { it.id == id }

    companion object {
        val EMPTY: SubscriptionsState = SubscriptionsState(emptyList(), null)
    }
}

/**
 * Документ хранения подписок `dppass.subscriptions` (D-36). Версия 2
 * (D-39, D-42) добавляет свои серверы (`inline` вместо `url`), срок
 * автообновления и время последней проверки; версия 3 (D-53) — признак
 * «имя задал пользователь» (`name_by_user`); версия 4 (D-94) — профиль
 * маршрутизации поставщика, прежний профиль и согласие на его списки
 * (`provider_profile`, `provider_profile_previous`, `use_provider_lists`).
 * Версии 1–3 читаются с значениями по умолчанию — их записал телефон
 * раньше; без признака имя показывается, как показывалось до версии 3
 * (название поставщика, если оно есть), без профиля — списков поставщика
 * нет, пока он их не пришлёт.
 *
 * В нём секреты — адрес подписки и идентификатор устройства (D-33):
 * документ пишется только в зашифрованное хранилище (D-19) и наружу не
 * отдаётся. Поэтому здесь — одно из немногих мест, где разрешён
 * `reveal()` (`code.forbidden`, правило `secret-reveal`, `tools/dpverify.toml`).
 *
 * Чтение строгое: неизвестная версия, неверный id или поле не того типа —
 * отказ целиком; повреждённое хранилище уходит в карантин вызывающим, а
 * не читается наполовину.
 */
object SubscriptionCodec {
    const val FORMAT: String = "dppass.subscriptions"
    const val VERSION: Int = 4
    private val READABLE = setOf(1, 2, 3, 4)

    fun write(state: SubscriptionsState): String = Json.write(
        Json.obj(
            "format" to Json.str(FORMAT),
            "format_version" to Json.num(VERSION),
            "active" to state.activeId?.let { Json.str(it.value) },
            "items" to Json.arr(state.items.map(::item)),
        ),
        pretty = false,
    )

    private fun item(s: Subscription): JsonObject {
        val m = s.metadata
        return Json.obj(
            "id" to Json.str(s.id.value),
            "name" to Json.str(s.name),
            "name_by_user" to Json.bool(s.nameByUser),
            "url" to (s.source as? SubscriptionSource.Url)?.let { Json.str(it.url.reveal()) },
            "inline" to (s.source as? SubscriptionSource.Inline)?.let { Json.str(it.body.reveal()) },
            // 0 — автообновление выключено; поля нет (версия 1) — по умолчанию.
            "auto_update_minutes" to Json.num(s.updatePolicy.intervalMinutes ?: 0),
            "only_unmetered" to Json.bool(s.updatePolicy.onlyUnmetered),
            "last_checked_at" to s.lastCheckedMillis?.let(Json::num),
            "device_id" to s.deviceId?.let { Json.str(it.reveal()) },
            "binding" to Json.str(if (s.binding == RoutingBinding.PROVIDER_ROUTING) "provider" else "user"),
            "provider_profile" to s.providerProfile?.let(::profile),
            "provider_profile_previous" to s.previousProviderProfile?.let(::profile),
            "use_provider_lists" to Json.bool(s.useProviderLists),
            "revision_counter" to Json.num(s.revisionCounter),
            "metadata" to Json.obj(
                "title" to Json.str(m.title),
                "update_interval_hours" to m.updateIntervalHours?.let(Json::num),
                "traffic" to m.traffic?.let { t ->
                    Json.obj(
                        "upload" to t.uploadBytes?.let(Json::num),
                        "download" to t.downloadBytes?.let(Json::num),
                        "total" to t.totalBytes?.let(Json::num),
                        "expire" to t.expireEpochSeconds?.let(Json::num),
                    )
                },
                "support_url" to Json.str(m.supportUrl),
                "web_page_url" to Json.str(m.webPageUrl),
                "announce" to Json.str(m.announce),
            ),
            "last_successful" to s.lastSuccessful?.let { r ->
                Json.obj(
                    "number" to Json.num(r.number),
                    "checksum" to Json.str(r.checksum),
                    "fetched_at" to Json.num(r.fetchedAtMillis),
                    "profiles" to Json.num(r.profileCount),
                )
            },
            "last_failed" to s.lastFailed?.let { f ->
                Json.obj(
                    "checksum" to Json.str(f.checksum),
                    "failed_at" to Json.num(f.failedAtMillis),
                    "code" to Json.str(f.reason.code.name),
                    "message" to Json.str(f.reason.message),
                )
            },
        )
    }

    private fun profile(p: ProviderProfile): JsonObject = Json.obj("text" to Json.str(p.text), "received_at" to Json.num(p.receivedAtMillis))

    private fun readProfile(o: JsonObject, key: String): ProviderProfile? = when (val v = o[key]) {
        null -> null
        is JsonObject -> {
            val text = v.str("text") ?: bad("$key.text")
            require(text.isNotBlank() && text.length <= ProviderProfile.MAX_CHARS) { "$key: профиль пуст или длиннее предела" }
            ProviderProfile(text, v.long("received_at") ?: bad("$key.received_at"))
        }
        else -> bad(key)
    }

    fun read(text: String): Outcome<SubscriptionsState> {
        val root = try {
            Json.parse(text) as? JsonObject
        } catch (e: JsonParseException) {
            null
        } ?: return Outcome.failure(DiagCode.STORAGE_CORRUPTED, "подписки: не JSON-объект")
        if ((root["format"] as? JsonString)?.value != FORMAT || (root["format_version"] as? JsonNumber)?.toIntOrNull() !in READABLE) {
            return Outcome.failure(DiagCode.FORMAT_VERSION_UNSUPPORTED, "подписки: неизвестный формат хранения")
        }
        return try {
            val items = (root["items"] as? JsonArray ?: bad("items")).items.map { readItem(it) }
            require(items.map { it.id }.toSet().size == items.size) { "повторный id подписки" }
            val active = (root["active"] as? JsonString)?.value?.let(::id)
            require(active == null || items.any { it.id == active }) { "применённой подписки нет в списке" }
            Outcome.Success(SubscriptionsState(items, active))
        } catch (e: IllegalArgumentException) {
            Outcome.failure(DiagCode.STORAGE_CORRUPTED, "подписки: ${e.message}")
        }
    }

    private fun readItem(v: JsonValue): Subscription {
        val o = v as? JsonObject ?: bad("items[]")
        val m = o["metadata"] as? JsonObject ?: bad("metadata")
        val traffic = (m["traffic"] as? JsonObject)?.let { t ->
            TrafficInfo(t.long("upload"), t.long("download"), t.long("total"), t.long("expire"))
        }
        val ok = (o["last_successful"] as? JsonObject)?.let { r ->
            SubscriptionRevision(
                r.long("number") ?: bad("number"),
                r.str("checksum") ?: bad("checksum"),
                r.long("fetched_at") ?: bad("fetched_at"),
                (r.long("profiles") ?: bad("profiles")).toInt(),
            )
        }
        val failed = (o["last_failed"] as? JsonObject)?.let { f ->
            val code = DiagCode.entries.firstOrNull { it.name == f.str("code") } ?: DiagCode.SUBSCRIPTION_FETCH_FAILED
            FailedRevision(f.str("checksum"), f.long("failed_at") ?: bad("failed_at"), Diagnostic.error(code, f.str("message") ?: ""))
        }
        val url = o.str("url")
        val inline = o.str("inline")
        require((url == null) != (inline == null)) { "у подписки ровно один источник: url или inline" }
        val interval = o.long("auto_update_minutes")
        require(interval == null || interval in 0..(30L * 24 * 60)) { "срок автообновления вне 0..30 суток" }
        return Subscription(
            id = id(o.str("id") ?: bad("id")),
            name = o.str("name") ?: bad("name"),
            nameByUser = o.bool("name_by_user") ?: false,
            source = if (url != null) SubscriptionSource.Url(Secret(url)) else SubscriptionSource.Inline(Secret(inline!!)),
            updatePolicy = UpdatePolicy(
                intervalMinutes = when (interval) {
                    null -> UpdatePolicy.DEFAULT_INTERVAL_MINUTES
                    0L -> null
                    else -> interval
                },
                onlyUnmetered = o.bool("only_unmetered") ?: false,
            ),
            lastCheckedMillis = o.long("last_checked_at"),
            binding = if (o.str("binding") == "provider") RoutingBinding.PROVIDER_ROUTING else RoutingBinding.USER_ROUTING,
            metadata = SubscriptionMetadata(
                title = m.str("title"),
                updateIntervalHours = m.long("update_interval_hours")?.toInt(),
                traffic = traffic,
                supportUrl = m.str("support_url"),
                webPageUrl = m.str("web_page_url"),
                announce = m.str("announce"),
            ),
            lastSuccessful = ok,
            lastFailed = failed,
            revisionCounter = o.long("revision_counter") ?: 0,
            deviceId = o.str("device_id")?.let { d ->
                require(DeviceId.FORMAT.matches(d)) { "идентификатор устройства не по формату" }
                Secret(d)
            },
            providerProfile = readProfile(o, "provider_profile"),
            previousProviderProfile = readProfile(o, "provider_profile_previous"),
            useProviderLists = o.bool("use_provider_lists") ?: false,
        )
    }

    private fun id(v: String): SubscriptionId {
        require(Ids.isValid(v)) { "id подписки не по формату" }
        return SubscriptionId(v)
    }

    private fun bad(what: String): Nothing = throw IllegalArgumentException("нет или не того типа: $what")

    private fun JsonObject.str(key: String): String? = when (val v = this[key]) {
        null -> null
        is JsonString -> v.value
        else -> bad(key)
    }

    private fun JsonObject.bool(key: String): Boolean? = when (val v = this[key]) {
        null -> null
        is com.dpsmpx.dppass.core.JsonBool -> v.value
        else -> bad(key)
    }

    private fun JsonObject.long(key: String): Long? = when (val v = this[key]) {
        null -> null
        is JsonNumber -> v.toLongOrNull() ?: bad(key)
        else -> bad(key)
    }
}
