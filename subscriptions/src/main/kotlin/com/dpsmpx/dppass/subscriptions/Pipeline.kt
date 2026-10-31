package com.dpsmpx.dppass.subscriptions

import com.dpsmpx.dppass.config.ConfigLimits
import com.dpsmpx.dppass.config.ConfigLoader
import com.dpsmpx.dppass.config.ConfigValidator
import com.dpsmpx.dppass.config.ServerProfile
import com.dpsmpx.dppass.core.Checksums
import com.dpsmpx.dppass.core.Clock
import com.dpsmpx.dppass.core.ProfileId
import com.dpsmpx.dppass.diagnostics.DiagCode
import com.dpsmpx.dppass.diagnostics.Diagnostic
import com.dpsmpx.dppass.diagnostics.Outcome
import com.dpsmpx.dppass.routing.DnsPolicy
import com.dpsmpx.dppass.routing.Layers
import com.dpsmpx.dppass.routing.RoutingPolicy
import java.util.Base64

/** Что извлечено из тела подписки до проверок. */
data class DecodedPayload(
    val profiles: List<ServerProfile>,
    val directives: Map<String, String>,
    /** Маршрутизация и DNS поставщика, если тело — документ DPpass. */
    val providerRouting: RoutingPolicy?,
    val providerDns: DnsPolicy?,
    /**
     * Место каждого профиля в теле — путь находок о нём: у списка ссылок —
     * `entry[k]`, номер записи среди всех записей тела (пропущенные тоже
     * считаются); у документа — `profiles[i]`. Так «запись 3» в находке
     * проверки или фильтра ядра — та же, что у разбора.
     */
    val paths: List<String> = profiles.indices.map { "profiles[$it]" },
    /**
     * Профиль маршрутизации поставщика из тела (D-94): строка `#routing:`
     * или ссылка `happ://routing/…` среди записей; null — нет.
     */
    val providerProfile: String? = null,
) {
    init {
        require(paths.size == profiles.size) { "путь — у каждого профиля" }
    }
}

/**
 * Распознавание тела подписки: документ DPpass, список ссылок или
 * список ссылок в base64. Всё прочее — SUBSCRIPTION_FORMAT_UNKNOWN без
 * цитаты тела.
 */
object PayloadDecoder {
    fun decode(bytes: ByteArray, idPrefix: String, maxEntries: Int): Outcome<DecodedPayload> {
        val text = String(bytes, Charsets.UTF_8).removePrefix("\uFEFF").trim()
        if (text.isEmpty()) return Outcome.failure(DiagCode.SUBSCRIPTION_EMPTY, "подписка пуста")
        if (text.startsWith("{")) return native(text)
        if (looksLikeLinkList(text)) return links(text, idPrefix, maxEntries)
        val decoded = base64(text) ?: return Outcome.failure(DiagCode.SUBSCRIPTION_FORMAT_UNKNOWN, "формат подписки не распознан")
        if (looksLikeLinkList(decoded)) return links(decoded, idPrefix, maxEntries)
        return Outcome.failure(DiagCode.SUBSCRIPTION_FORMAT_UNKNOWN, "после base64 — не список ссылок")
    }

    private fun native(text: String): Outcome<DecodedPayload> = when (val r = ConfigLoader().load(text)) {
        is Outcome.Failure -> Outcome.Failure(
            listOf(Diagnostic.error(DiagCode.SUBSCRIPTION_FORMAT_UNKNOWN, "документ DPpass в подписке не прошёл проверку").copy(causes = r.diagnostics)),
        )
        is Outcome.Success -> Outcome.Success(
            DecodedPayload(r.value.ir.profiles, emptyMap(), r.value.ir.routing, r.value.ir.dns),
            r.diagnostics,
        )
    }

    private fun looksLikeLinkList(text: String): Boolean {
        val lines = text.lineSequence().map { it.trim() }.filter { it.isNotEmpty() && !it.startsWith("#") }.take(50).toList()
        return lines.isNotEmpty() && lines.all { ShareLinkParser.isLink(it) }
    }

    private fun links(text: String, idPrefix: String, maxEntries: Int): Outcome<DecodedPayload> {
        val notes = mutableListOf<Diagnostic>()
        val directives = LinkedHashMap<String, String>()
        val profiles = mutableListOf<ServerProfile>()
        val paths = mutableListOf<String>()
        var routingLink: String? = null
        var entry = 0
        for (raw in text.lineSequence()) {
            val line = raw.trim()
            if (line.isEmpty()) continue
            if (line.startsWith("#")) {
                val body = line.removePrefix("#").trim()
                val colon = body.indexOf(':')
                if (colon > 0) directives.putIfAbsent(body.substring(0, colon).trim().lowercase(), body.substring(colon + 1).trim())
                continue
            }
            if (line.startsWith(ROUTING_LINK, ignoreCase = true)) {
                // Профиль маршрутизации поставщика (D-94) — не сервер: номера записи не занимает.
                if (routingLink == null) routingLink = line
                continue
            }
            if (entry >= maxEntries) {
                notes += Diagnostic.warning(DiagCode.SUBSCRIPTION_ENTRY_SKIPPED, "записей больше $maxEntries — остальные не читались")
                break
            }
            val path = "entry[$entry]"
            entry++
            when (val r = ShareLinkParser.parse(line, idPrefix)) {
                is Outcome.Success -> {
                    profiles += r.value
                    paths += path
                    // Находки принятой записи (отброшенный параметр, D-48) — с местом записи.
                    notes += r.diagnostics.map { it.copy(path = it.path ?: path) }
                }
                is Outcome.Failure -> notes += Diagnostic.warning(DiagCode.SUBSCRIPTION_ENTRY_SKIPPED, "запись пропущена", path).copy(causes = r.diagnostics)
            }
        }
        val profile = directives[MetadataParser.ROUTING]?.takeIf { it.isNotBlank() } ?: routingLink
        return Outcome.Success(DecodedPayload(profiles, directives, null, null, paths, profile), notes)
    }

    /** Ссылка профиля маршрутизации в теле подписки (D-94; `HAPP_SOURCE_AUDIT.md`, §7). */
    private const val ROUTING_LINK = "happ://routing/"

    private fun base64(text: String): String? {
        val compact = text.filterNot { it.isWhitespace() }
        if (compact.isEmpty() || compact.length % 4 == 1) return null
        val decoders = listOf(Base64.getDecoder(), Base64.getUrlDecoder())
        for (d in decoders) {
            val padded = compact + "=".repeat((4 - compact.length % 4) % 4)
            val bytes = runCatching { d.decode(padded) }.getOrNull() ?: continue
            return String(bytes, Charsets.UTF_8)
        }
        return null
    }
}

/**
 * Готовый к активации результат обновления подписки. Сама активация
 * (компиляция, проверка ядром, проверка здоровья, замена) — в
 * `connection/`: подписка не знает про ядро.
 */
data class SubscriptionCandidate(
    val subscription: Subscription,
    val revision: SubscriptionRevision,
    val metadata: SubscriptionMetadata,
    val profiles: List<ServerProfile>,
    val providerRouting: RoutingPolicy?,
    val providerDns: DnsPolicy?,
    /**
     * Профиль маршрутизации поставщика из ответа (D-94): заголовок
     * `routing`, иначе тело; null — в ответе его нет. Принимается в
     * подписку при активации ревизии ([Subscription.withProviderProfile]).
     */
    val providerProfile: String? = null,
    /**
     * Тело — документ DPpass: поставщик прислал маршрутизацию и DNS, даже
     * если подписка к ним не привязана и [providerRouting] с [providerDns]
     * пусты (D-98). Принимается в подписку с ревизией.
     */
    val offersPolicy: Boolean = false,
)

sealed interface UpdateResult {
    val diagnostics: List<Diagnostic>

    /** Тело не изменилось с последней удачной ревизии. */
    data class Unchanged(val subscription: Subscription, override val diagnostics: List<Diagnostic>) : UpdateResult

    /** Новая ревизия прошла проверки подписки; ждёт активации. */
    data class Ready(val candidate: SubscriptionCandidate, override val diagnostics: List<Diagnostic>) : UpdateResult

    /** Отказ: подписка с записанной неудачей; прежняя удачная ревизия не тронута. */
    data class Failed(val subscription: Subscription, override val diagnostics: List<Diagnostic>) : UpdateResult
}

/**
 * Конвейер подписки (D-08):
 * загрузка → целостность (размер, пустота, контрольная сумма) → разбор →
 * нормализация и проверка записей → фильтр по возможностям ядра →
 * кандидат на активацию.
 *
 * Ни на одном шаге старая удачная ревизия не меняется: при отказе
 * возвращается подписка с [Subscription.lastFailed], и только.
 */
class SubscriptionUpdater(
    private val fetcher: SubscriptionFetcher,
    private val clock: Clock,
    /** Версия приложения — для собственного `User-Agent` (D-33). */
    private val appVersion: String,
) {
    suspend fun update(subscription: Subscription, filter: ProfileFilter): UpdateResult {
        val notes = mutableListOf<Diagnostic>()
        fun fail(d: Diagnostic, checksum: String? = null): UpdateResult.Failed =
            UpdateResult.Failed(subscription.recordFailure(FailedRevision(checksum, clock.nowMillis(), d)), notes + d)

        val request = SubscriptionRequest.of(subscription, appVersion)
        val payload = when (val f = fetcher.fetch(request, subscription.fetchPolicy)) {
            is Outcome.Failure -> return fail(
                Diagnostic.error(DiagCode.SUBSCRIPTION_FETCH_FAILED, "подписка «${subscription.name}» не загружена").copy(causes = f.diagnostics),
            )
            is Outcome.Success -> f.value
        }
        deviceRefusal(payload.headers, subscription)?.let { return fail(it) }
        if (payload.bytes.size > subscription.fetchPolicy.maxBytes) {
            return fail(Diagnostic.error(DiagCode.SUBSCRIPTION_TOO_LARGE, "больше ${subscription.fetchPolicy.maxBytes} байт"))
        }
        val headerProfile = MetadataParser.routing(payload.headers)
        // Профиль из заголовка — часть ревизии (D-94): другой профиль при том же теле — не «без изменений».
        val checksum = if (headerProfile == null) {
            Checksums.sha256(payload.bytes)
        } else {
            Checksums.sha256(payload.bytes + byteArrayOf(0) + headerProfile.toByteArray(Charsets.UTF_8))
        }
        if (subscription.lastSuccessful?.checksum == checksum) {
            return UpdateResult.Unchanged(subscription, listOf(Diagnostic.info(DiagCode.SUBSCRIPTION_UNCHANGED, "содержимое не изменилось")))
        }
        val decoded = when (val d = PayloadDecoder.decode(payload.bytes, subscription.id.value, subscription.fetchPolicy.maxEntries)) {
            is Outcome.Failure -> return fail(d.errors.first().let { e -> e.copy(causes = e.causes + (d.diagnostics - e)) }, checksum)
            is Outcome.Success -> d.value.also { notes += d.diagnostics }
        }
        val meta = MetadataParser.parse(payload.headers, decoded.directives)
        notes += meta.notes
        val profile = (headerProfile ?: decoded.providerProfile)?.takeIf { p ->
            (p.length <= ProviderProfile.MAX_CHARS).also { fits ->
                if (!fits) {
                    notes += Diagnostic.warning(
                        DiagCode.SUBSCRIPTION_METADATA_INVALID,
                        "routing: профиль маршрутизации длиннее ${ProviderProfile.MAX_CHARS / 1024} КБ — не принят",
                    )
                }
            }
        }

        val valid = mutableListOf<ServerProfile>()
        val validPaths = mutableListOf<String>()
        val seen = HashMap<ProfileId, ServerProfile>()
        val limit = ConfigLimits().maxProfiles
        for ((i, p) in decoded.profiles.withIndex()) {
            val at = decoded.paths[i]
            val problems = ConfigValidator.validateProfile(p, at)
            val first = seen[p.id]
            when {
                problems.any { it.isError } ->
                    notes += Diagnostic.warning(DiagCode.SUBSCRIPTION_ENTRY_SKIPPED, "сервер «${p.name}» пропущен: не прошёл проверку", at)
                        .copy(causes = problems)
                // id ссылки — от всего, кроме имени: тот же id — тот же сервер с теми же
                // настройками. Второй такой профиль сделал бы конфигурацию нечитаемой (ID_DUPLICATE).
                first != null ->
                    notes += Diagnostic.warning(
                        DiagCode.SUBSCRIPTION_ENTRY_SKIPPED,
                        "сервер «${p.name}» пропущен: та же запись, что «${first.name}», отличается только именем",
                        at,
                    )
                // Больше профилей, чем принимает документ, — конфигурация не прочиталась бы.
                valid.size >= limit ->
                    notes += Diagnostic.warning(DiagCode.SUBSCRIPTION_ENTRY_SKIPPED, "сервер «${p.name}» пропущен: серверов больше $limit", at)
                else -> {
                    valid += p
                    validPaths += at
                    seen[p.id] = p
                }
            }
        }
        val filtered = filter.filter(valid, validPaths)
        notes += filtered.notes
        if (filtered.usable.isEmpty()) {
            return fail(Diagnostic.error(DiagCode.SUBSCRIPTION_NO_USABLE_SERVERS, "в подписке нет ни одного пригодного сервера"), checksum)
        }
        val useProvider = subscription.binding == RoutingBinding.PROVIDER_ROUTING
        if (!useProvider && (decoded.providerRouting != null || decoded.providerDns != null)) {
            notes += Diagnostic.warning(
                DiagCode.SUBSCRIPTION_DIRECTIVE_IGNORED,
                "маршрутизация и DNS поставщика не применены: у подписки выбрана маршрутизация пользователя " +
                    "(включить — у подписки, «Маршрутизация поставщика»)",
            )
        }
        // Привязанная маршрутизация (D-98): id слоёв своих настроек заняты — ревизия не принимается (D-05).
        if (useProvider) {
            val clash = Layers.reserved(decoded.providerRouting, decoded.providerDns)
            if (clash.isNotEmpty()) return fail(clash.first().copy(causes = clash.drop(1)), checksum)
        }
        val revision = SubscriptionRevision(subscription.revisionCounter + 1, checksum, payload.fetchedAtMillis, filtered.usable.size)
        val candidate = SubscriptionCandidate(
            subscription,
            revision,
            meta.metadata,
            filtered.usable,
            decoded.providerRouting.takeIf { useProvider },
            decoded.providerDns.takeIf { useProvider },
            profile,
            offersPolicy = decoded.providerRouting != null || decoded.providerDns != null,
        )
        return UpdateResult.Ready(candidate, notes)
    }

    /**
     * Отказ поставщика из-за лимита устройств (Remnawave, D-33). Тело
     * такого ответа — заглушка («App not supported»), а не серверы: в
     * ревизию оно не идёт, удачная ревизия остаётся прежней (D-08).
     */
    private fun deviceRefusal(headers: Map<String, String>, subscription: Subscription): Diagnostic? {
        val lower = headers.mapKeys { it.key.lowercase() }
        fun flag(name: String) = lower[name]?.trim()?.lowercase() == "true"
        val who = "поставщик подписки «${subscription.name}»"
        return when {
            flag("x-hwid-max-devices-reached") -> Diagnostic.error(
                DiagCode.SUBSCRIPTION_DEVICE_LIMIT_REACHED,
                "$who: лимит устройств исчерпан — удалите неиспользуемое устройство у поставщика; вместо серверов прислана заглушка",
            )
            flag("x-hwid-not-supported") -> Diagnostic.error(
                DiagCode.SUBSCRIPTION_DEVICE_ID_REQUIRED,
                if (subscription.deviceId == null) {
                    "$who отдаёт серверы только с идентификатором устройства; его можно включить для этой подписки — " +
                        "случайный, свой у каждой подписки, без данных устройства"
                } else {
                    "$who не принял идентификатор устройства этой подписки; вместо серверов прислана заглушка"
                },
            )
            else -> null
        }
    }
}
