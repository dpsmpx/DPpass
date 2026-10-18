package com.dpsmpx.dppass.app.ui

import com.dpsmpx.dppass.config.ProtocolKind
import com.dpsmpx.dppass.config.SecurityKind
import com.dpsmpx.dppass.config.ServerProfile
import com.dpsmpx.dppass.config.TransportKind
import com.dpsmpx.dppass.connection.CandidateHealth
import com.dpsmpx.dppass.connection.HealthState
import com.dpsmpx.dppass.core.ProfileId
import com.dpsmpx.dppass.core.SubscriptionId
import com.dpsmpx.dppass.diagnostics.DiagCode
import com.dpsmpx.dppass.diagnostics.Diagnostic
import com.dpsmpx.dppass.diagnostics.FailureKind
import com.dpsmpx.dppass.network.LatencyResult
import com.dpsmpx.dppass.subscriptions.SubscriptionSource
import com.dpsmpx.dppass.subscriptions.SubscriptionsState
import java.util.Locale
import kotlin.math.roundToLong

// Логика экранов без Android (D-34): что показать, решается здесь и
// проверяется на хосте (app/src/test); экраны только раскладывают это по Views.

/** Здоровье строки сервера: что известно о нём с запуска процесса (D-15). */
enum class RowHealth { UNKNOWN, HEALTHY, FAILED, PAUSED }

data class ServerRow(
    val id: ProfileId,
    val name: String,
    /** Протокол, защита и транспорт: «VLESS · REALITY · TCP». */
    val summary: String,
    val health: RowHealth,
    /** Сколько ещё секунд пауза после отказа ([RowHealth.PAUSED]). */
    val pauseSeconds: Long,
    val lastFailure: FailureKind?,
    val selected: Boolean,
    val connected: Boolean,
    /** Последний замер задержки (D-41). */
    val latency: LatencyLabel = LatencyLabel.UNKNOWN,
    /** Флаг из начала имени или первая буква — для кружка в строке. */
    val avatar: String = Avatar.of(name),
)

/** Уровень задержки для цвета значка (D-41): не «работает», а «далеко ли». */
enum class LatencyLevel { GOOD, FAIR, POOR, FAILED, UDP, UNKNOWN }

data class LatencyLabel(val level: LatencyLevel, val millis: Long? = null) {
    companion object {
        val UNKNOWN: LatencyLabel = LatencyLabel(LatencyLevel.UNKNOWN)
        const val GOOD_MILLIS: Long = 150
        const val FAIR_MILLIS: Long = 400

        fun of(r: LatencyResult?): LatencyLabel = when (r) {
            null -> UNKNOWN
            LatencyResult.NotTcp -> LatencyLabel(LatencyLevel.UDP)
            is LatencyResult.Failed -> LatencyLabel(LatencyLevel.FAILED)
            is LatencyResult.Measured -> LatencyLabel(
                when {
                    r.millis < GOOD_MILLIS -> LatencyLevel.GOOD
                    r.millis < FAIR_MILLIS -> LatencyLevel.FAIR
                    else -> LatencyLevel.POOR
                },
                r.millis,
            )
        }
    }
}

/**
 * Кружок сервера: флаг, если имя с него начинается (два символа
 * региональных индикаторов, как у поставщиков: «🇩🇪 Германия»), иначе
 * первая буква или цифра имени.
 */
object Avatar {
    fun of(name: String): String {
        val t = name.trim()
        if (t.length >= 4 && isRegional(t.codePointAt(0))) {
            val second = t.codePointAt(Character.charCount(t.codePointAt(0)))
            if (isRegional(second)) return String(Character.toChars(t.codePointAt(0))) + String(Character.toChars(second))
        }
        val first = t.firstOrNull { it.isLetterOrDigit() } ?: return "•"
        return first.uppercaseChar().toString()
    }

    /** Имя без флага в начале — флаг уже в кружке. */
    fun stripFlag(name: String): String {
        val a = of(name)
        return if (a.length == 4 && name.trim().startsWith(a)) name.trim().removePrefix(a).trim().ifEmpty { name } else name
    }

    private fun isRegional(cp: Int): Boolean = cp in 0x1F1E6..0x1F1FF
}

object ServerList {
    /**
     * Строки в порядке конфигурации — порядок пользователя или поставщика,
     * а не план (план меняется от здоровья, список — нет).
     */
    fun rows(
        profiles: List<ServerProfile>,
        health: (ProfileId) -> CandidateHealth,
        selected: ProfileId?,
        connected: ProfileId?,
        nowMillis: Long,
        latency: (ProfileId) -> LatencyResult? = { null },
    ): List<ServerRow> {
        val chosen = effectiveSelection(profiles, selected)
        return profiles.map { p ->
            val h = health(p.id)
            val paused = h.state == HealthState.FAILED && h.backoffUntilMillis > nowMillis
            ServerRow(
                id = p.id,
                name = p.name,
                summary = summary(p),
                health = when {
                    paused -> RowHealth.PAUSED
                    h.state == HealthState.HEALTHY -> RowHealth.HEALTHY
                    h.state == HealthState.FAILED -> RowHealth.FAILED
                    else -> RowHealth.UNKNOWN
                },
                pauseSeconds = if (paused) (h.backoffUntilMillis - nowMillis + 999) / 1000 else 0,
                lastFailure = h.lastFailure?.kind,
                selected = p.id == chosen,
                connected = p.id == connected,
                latency = LatencyLabel.of(latency(p.id)),
            )
        }
    }

    /** Поиск: подстрока имени или описания, без учёта регистра. */
    fun filter(rows: List<ServerRow>, query: String): List<ServerRow> {
        val q = query.trim().lowercase()
        if (q.isEmpty()) return rows
        return rows.filter { q in it.name.lowercase() || q in it.summary.lowercase() }
    }

    /** По задержке: измеренные — по возрастанию, остальные — после, в прежнем порядке. */
    fun byLatency(rows: List<ServerRow>): List<ServerRow> = rows.withIndex()
        .sortedWith(compareBy({ it.value.latency.millis ?: Long.MAX_VALUE }, { it.index }))
        .map { it.value }

    /** Выбор, которого в конфигурации больше нет (подписка обновилась), — «автоматически». */
    fun effectiveSelection(profiles: List<ServerProfile>, selected: ProfileId?): ProfileId? =
        selected?.takeIf { id -> profiles.any { it.id == id } }

    fun summary(p: ServerProfile): String {
        val parts = mutableListOf(
            when (p.protocol.kind) {
                ProtocolKind.VLESS -> "VLESS"
                ProtocolKind.TROJAN -> "Trojan"
                ProtocolKind.SHADOWSOCKS -> "Shadowsocks 2022"
                ProtocolKind.HYSTERIA2 -> "Hysteria2"
                ProtocolKind.SOCKS -> "SOCKS5"
            },
        )
        // У Hysteria2 TLS — часть протокола, а транспорт — QUIC.
        if (p.protocol.kind != ProtocolKind.HYSTERIA2) {
            when (p.security.kind) {
                SecurityKind.TLS -> parts += "TLS"
                SecurityKind.REALITY -> parts += "REALITY"
                SecurityKind.NONE -> Unit
            }
        }
        when (p.transport.kind) {
            TransportKind.TCP -> parts += "TCP"
            TransportKind.WEBSOCKET -> parts += "WebSocket"
            TransportKind.GRPC -> parts += "gRPC"
            TransportKind.XHTTP -> parts += "XHTTP"
            TransportKind.HTTPUPGRADE -> parts += "HTTPUpgrade"
            TransportKind.NATIVE -> if (p.protocol.kind == ProtocolKind.HYSTERIA2) parts += "QUIC"
        }
        return parts.joinToString(SEPARATOR)
    }

    const val SEPARATOR: String = " · "
}

/** Что сейчас активно: своя конфигурация, подписка или ничего (источник записи активации). */
sealed interface ConfigSource {
    data object None : ConfigSource

    data object Own : ConfigSource

    data class FromSubscription(val id: SubscriptionId) : ConfigSource

    companion object {
        /** `ActivationRecord.source`: `user-import` или `subscription:<id>#<ревизия>`. */
        fun of(source: String?): ConfigSource = when {
            source == null -> None
            source.startsWith(SUBSCRIPTION) -> FromSubscription(SubscriptionId(source.removePrefix(SUBSCRIPTION).substringBefore('#')))
            else -> Own
        }

        private const val SUBSCRIPTION = "subscription:"
    }
}

data class SubscriptionRow(
    val id: SubscriptionId,
    val name: String,
    /** Свои серверы (D-42), а не подписка по адресу. */
    val inline: Boolean = false,
    /** Срок автообновления, минуты (D-39); null — только вручную. */
    val autoUpdateMinutes: Long? = null,
    /** Доля использованного трафика, 0…100; null — предела нет или неизвестен. */
    val usedPercent: Int? = null,
    /** Сколько дней до конца срока (0 — сегодня); null — срока нет или он прошёл. */
    val daysLeft: Long? = null,
    /** Страница и поддержка поставщика — только https:// (`MetadataParser`). */
    val pageUrl: String? = null,
    val supportUrl: String? = null,
    /** Подсказка поставщика об интервале обновления, часы — показывается, не применяется (D-11, D-39). */
    val providerIntervalHours: Int? = null,
    /** Её серверы — серверы активной конфигурации сейчас. */
    val active: Boolean,
    val profileCount: Int?,
    val updatedAtMillis: Long?,
    /** Последняя загрузка не удалась (позже последней удачной). */
    val failure: Diagnostic?,
    val usedBytes: Long?,
    val totalBytes: Long?,
    val expireMillis: Long?,
    val expired: Boolean,
    val deviceIdEnabled: Boolean,
    /** Объявление поставщика — текст как есть, без управляющих символов и не длиннее [ANNOUNCE_LIMIT]. */
    val announce: String?,
    /** Сколько записей последнего разбора не стали серверами; null — в этом запуске не разбиралась. */
    val skipped: Int? = null,
)

const val ANNOUNCE_LIMIT: Int = 300
private const val DAY_MILLIS: Long = 24 * 60 * 60_000L

object SubscriptionList {
    /** [skipped] — сколько записей последнего разбора подписки не стали серверами (`SkippedEntries`). */
    fun rows(
        state: SubscriptionsState,
        source: ConfigSource,
        nowMillis: Long,
        skipped: (SubscriptionId) -> Int? = { null },
    ): List<SubscriptionRow> = state.items.map { s ->
        val ok = s.lastSuccessful
        val failed = s.lastFailed?.takeIf { f -> ok == null || f.failedAtMillis >= ok.fetchedAtMillis }
        val traffic = s.metadata.traffic
        val used = traffic?.let { t -> if (t.uploadBytes == null && t.downloadBytes == null) null else (t.uploadBytes ?: 0) + (t.downloadBytes ?: 0) }
        val expire = traffic?.expireEpochSeconds?.takeIf { it > 0 }?.let { it * 1000 }
        val total = traffic?.totalBytes?.takeIf { it > 0 }
        SubscriptionRow(
            id = s.id,
            name = s.displayName,
            inline = s.source is SubscriptionSource.Inline,
            autoUpdateMinutes = s.updatePolicy.intervalMinutes,
            usedPercent = if (used != null && total != null) ((used * 100) / total).coerceIn(0, 100).toInt() else null,
            daysLeft = expire?.takeIf { it > nowMillis }?.let { (it - nowMillis) / DAY_MILLIS },
            pageUrl = s.metadata.webPageUrl,
            supportUrl = s.metadata.supportUrl,
            providerIntervalHours = s.metadata.updateIntervalHours,
            active = source == ConfigSource.FromSubscription(s.id),
            profileCount = ok?.profileCount,
            updatedAtMillis = ok?.fetchedAtMillis,
            failure = failed?.reason,
            usedBytes = used,
            // 0 у поставщиков — «без предела».
            totalBytes = traffic?.totalBytes?.takeIf { it > 0 },
            expireMillis = expire,
            expired = expire != null && expire <= nowMillis,
            deviceIdEnabled = s.deviceId != null,
            announce = s.metadata.announce?.let(::plain)?.takeIf { it.isNotEmpty() },
            skipped = skipped(s.id),
        )
    }

    /**
     * Номер записи ответа поставщика с единицы; null — номера нет. `entry[i]`
     * — номер записи только у той, что не разобрал разбор ссылок
     * (`SUBSCRIPTION_ENTRY_SKIPPED`). У фильтра ядра (`EngineProfileFilter`)
     * `entry[i]` считается среди уже разобранных серверов и после пропусков
     * указал бы не на ту запись; имя сервера там — в сообщении.
     */
    fun entryNumber(d: Diagnostic): Int? =
        d.path?.takeIf { d.code == DiagCode.SUBSCRIPTION_ENTRY_SKIPPED }?.let { ENTRY.matchEntire(it) }?.groupValues?.get(1)?.toIntOrNull()?.plus(1)

    private val ENTRY = Regex("""entry\[(\d+)]""")

    /** Текст поставщика — только печатаемые символы и переводы строк; лишнее обрезается. */
    fun plain(text: String): String = text
        .filter { it == '\n' || !it.isISOControl() }
        .trim()
        .let { if (it.length > ANNOUNCE_LIMIT) it.take(ANNOUNCE_LIMIT - 1) + "…" else it }
}

object Formats {
    /** Скорость: «1.2 МБ/с». */
    fun speed(bytesPerSecond: Long, units: List<String>, locale: Locale, perSecond: String): String = bytes(bytesPerSecond, units, locale) + perSecond

    /** Длительность: «4:05», «1:02:03». */
    fun duration(millis: Long): String {
        val total = (millis / 1000).coerceAtLeast(0)
        val h = total / 3600
        val m = (total % 3600) / 60
        val sec = total % 60
        return if (h > 0) "%d:%02d:%02d".format(Locale.ROOT, h, m, sec) else "%d:%02d".format(Locale.ROOT, m, sec)
    }

    /**
     * Байты в единицах [units] (Б, КБ, МБ, ГБ, ТБ — по 1024): до 10 —
     * с одним знаком после запятой, дальше — целым.
     */
    fun bytes(n: Long, units: List<String>, locale: Locale): String {
        require(units.isNotEmpty())
        var value = n.coerceAtLeast(0).toDouble()
        var unit = 0
        while (value >= 1024 && unit < units.lastIndex) {
            value /= 1024
            unit++
        }
        val text = if (unit == 0 || value >= 10) value.roundToLong().toString() else String.format(locale, "%.1f", value)
        return "$text ${units[unit]}"
    }
}

/**
 * Сохранённое не прочитать: ключ данных утрачен (`STORAGE_DATA_KEY_LOST`,
 * D-19). Выход — сброс хранилища, и только действием пользователя: такой
 * отказ показывается с кнопкой сброса — в окне отказа и сразу при запуске.
 */
object StorageLost {
    /** Первая находка об утрате ключа — сама или в цепочке причин. */
    fun find(diagnostics: List<Diagnostic>): Diagnostic? = diagnostics.firstOrNull(::isLost)

    fun isLost(d: Diagnostic): Boolean = d.code == DiagCode.STORAGE_DATA_KEY_LOST || d.causes.any(::isLost)
}
