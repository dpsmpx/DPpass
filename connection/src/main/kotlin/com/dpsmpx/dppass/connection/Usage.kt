package com.dpsmpx.dppass.connection

import com.dpsmpx.dppass.core.Clock
import com.dpsmpx.dppass.core.Json
import com.dpsmpx.dppass.core.JsonArray
import com.dpsmpx.dppass.core.JsonNull
import com.dpsmpx.dppass.core.JsonNumber
import com.dpsmpx.dppass.core.JsonObject
import com.dpsmpx.dppass.core.JsonParseException
import com.dpsmpx.dppass.core.JsonString
import com.dpsmpx.dppass.diagnostics.DiagCode
import com.dpsmpx.dppass.diagnostics.Diagnostic
import com.dpsmpx.dppass.diagnostics.Outcome
import com.dpsmpx.dppass.diagnostics.map
import com.dpsmpx.dppass.engine.TrafficStats
import com.dpsmpx.dppass.network.NetworkType
import com.dpsmpx.dppass.storage.BlobStore
import com.dpsmpx.dppass.storage.Quarantine
import java.time.Instant
import java.time.LocalDate
import java.time.ZoneId
import java.time.format.DateTimeParseException
import java.util.Locale

/** Байты через сервер: отдано и получено (D-92). */
data class UsageBytes(val up: Long, val down: Long) {
    val total: Long get() = up + down

    operator fun plus(o: UsageBytes): UsageBytes = UsageBytes(up + o.up, down + o.down)

    companion object {
        val ZERO: UsageBytes = UsageBytes(0, 0)
    }
}

/**
 * Настройки учёта трафика (D-92): с какого числа месяца начинается
 * расчётный период — как у тарифа оператора — и порог мобильной сети за
 * период (null — без порога). Порог только предупреждает: туннель не
 * отключается.
 */
data class UsageSettings(val periodStartDay: Int = 1, val mobileLimitBytes: Long? = null) {
    companion object {
        val DAYS: IntRange = 1..31

        /** 1 ПиБ: больше — не порог, а опечатка. */
        const val MAX_LIMIT_BYTES: Long = 1L shl 50

        /** Гигабайт порога — 2^30 байт, как в подписях размеров обеих оболочек. */
        const val GIB: Long = 1L shl 30

        /** Порог из поля ввода: «15», «1,5» и «1.5» — гигабайты; не число, ноль или больше предела — null. */
        fun parseGigabytes(text: String): Long? {
            val gb = text.trim().replace(',', '.').toDoubleOrNull()?.takeIf { it > 0 && it.isFinite() } ?: return null
            return (gb * GIB).toLong().takeIf { it in 1..MAX_LIMIT_BYTES }
        }

        /** Порог для поля ввода: целые гигабайты — без дробной части, иначе до сотых. */
        fun gigabytes(bytes: Long): String =
            if (bytes % GIB == 0L) (bytes / GIB).toString() else String.format(Locale.ROOT, "%.2f", bytes.toDouble() / GIB).trimEnd('0').trimEnd('.')
    }
}

/** Порог мобильной сети пройден в периоде, начавшемся [periodStart], — сказать один раз. */
data class UsageAlert(val usedBytes: Long, val limitBytes: Long, val periodStart: LocalDate)

/**
 * Счёт на сейчас: за сегодня и за расчётный период [periodStart, periodEnd)
 * — по сетям под туннелем. [resetAtMillis] — сброс, если он был в этом
 * периоде: счёт идёт с него.
 */
data class UsageSummary(
    val today: Map<NetworkType, UsageBytes>,
    val period: Map<NetworkType, UsageBytes>,
    val periodStart: LocalDate,
    val periodEnd: LocalDate,
    val resetAtMillis: Long?,
    val settings: UsageSettings,
) {
    val todayTotal: UsageBytes get() = today.values.fold(UsageBytes.ZERO, UsageBytes::plus)
    val periodTotal: UsageBytes get() = period.values.fold(UsageBytes.ZERO, UsageBytes::plus)
    val mobilePeriodBytes: Long get() = period[NetworkType.MOBILE]?.total ?: 0

    /** Доля порога мобильной сети, 0…1 и больше; без порога — null. */
    val mobileLimitFraction: Double? get() = settings.mobileLimitBytes?.let { mobilePeriodBytes.toDouble() / it }
}

/**
 * Расчётный период (D-92): с дня [startDay] месяца до того же дня
 * следующего. В коротком месяце нет 29–31 числа — период начинается в его
 * последний день, как у операторов: никакой день не выпадает и не
 * считается дважды.
 */
object UsagePeriod {
    /** [начало, конец) периода, в который попадает [date]. */
    fun of(date: LocalDate, startDay: Int): Pair<LocalDate, LocalDate> {
        require(startDay in UsageSettings.DAYS) { "день начала периода — 1…31" }
        val here = startIn(date, startDay)
        val start = if (date >= here) here else startIn(date.minusMonths(1), startDay)
        return start to startIn(start.plusMonths(1), startDay)
    }

    private fun startIn(month: LocalDate, startDay: Int): LocalDate = month.withDayOfMonth(minOf(startDay, month.lengthOfMonth()))
}

/**
 * Приращения счётчиков ядра (D-92). Счётчики сеанса растут с нуля: первое
 * чтение — всё, что прошло с начала сеанса; убыль — новый сеанс ядра, его
 * счётчики и есть приращение. Свой экземпляр на каждый сеанс оболочки.
 */
class UsageMeter {
    private var last: TrafficStats? = null

    fun delta(stats: TrafficStats): UsageBytes {
        val prev = last
        last = stats
        if (prev == null || stats.uplinkBytes < prev.uplinkBytes || stats.downlinkBytes < prev.downlinkBytes) {
            return UsageBytes(stats.uplinkBytes.coerceAtLeast(0), stats.downlinkBytes.coerceAtLeast(0))
        }
        return UsageBytes(stats.uplinkBytes - prev.uplinkBytes, stats.downlinkBytes - prev.downlinkBytes)
    }
}

/** Что хранится: настройки, сутки по сетям, сброс и о каком периоде уже сказано. */
data class UsageState(
    val settings: UsageSettings = UsageSettings(),
    val days: Map<LocalDate, Map<NetworkType, UsageBytes>> = emptyMap(),
    val resetAtMillis: Long? = null,
    val alertedPeriod: LocalDate? = null,
)

object UsageCodec {
    const val FORMAT: String = "dppass.usage"
    const val VERSION: Int = 1

    /** Сети учёта: «нет сети» не бывает — трафик без известной сети считается в «другие». */
    val NETWORKS: List<NetworkType> = listOf(NetworkType.MOBILE, NetworkType.WIFI, NetworkType.ETHERNET, NetworkType.OTHER)

    fun write(s: UsageState): String = Json.write(
        Json.obj(
            "format" to Json.str(FORMAT),
            "format_version" to Json.num(VERSION),
            "period_start_day" to Json.num(s.settings.periodStartDay),
            "mobile_limit" to (s.settings.mobileLimitBytes?.let(Json::num) ?: JsonNull),
            "reset_at" to (s.resetAtMillis?.let(Json::num) ?: JsonNull),
            "alerted_period" to (s.alertedPeriod?.let { Json.str(it.toString()) } ?: JsonNull),
            "days" to Json.arr(
                s.days.toSortedMap().flatMap { (date, byNetwork) ->
                    NETWORKS.mapNotNull { n ->
                        byNetwork[n]?.takeIf { it.total > 0 }?.let { b ->
                            Json.obj("date" to Json.str(date.toString()), "network" to Json.str(n.name), "up" to Json.num(b.up), "down" to Json.num(b.down))
                        }
                    }
                },
            ),
        ),
        pretty = false,
    )

    fun read(text: String): Outcome<UsageState> {
        val root = try {
            Json.parse(text) as? JsonObject
        } catch (e: JsonParseException) {
            null
        } ?: return Outcome.failure(DiagCode.STORAGE_CORRUPTED, "учёт трафика — не объект JSON")
        fun bad(what: String): Outcome<UsageState> = Outcome.failure(DiagCode.STORAGE_CORRUPTED, "учёт трафика: $what")
        if ((root["format"] as? JsonString)?.value != FORMAT || (root["format_version"] as? JsonNumber)?.toIntOrNull() != VERSION) {
            return Outcome.failure(DiagCode.FORMAT_VERSION_UNSUPPORTED, "неизвестный формат учёта трафика")
        }
        root.fields.keys.firstOrNull { it !in KEYS }?.let { return bad("неизвестное поле «$it»") }
        val startDay = (root["period_start_day"] as? JsonNumber)?.toIntOrNull()?.takeIf { it in UsageSettings.DAYS } ?: return bad("period_start_day")
        val limit = when (val v = root["mobile_limit"]) {
            null, JsonNull -> null
            is JsonNumber -> v.toLongOrNull()?.takeIf { it in 1..UsageSettings.MAX_LIMIT_BYTES } ?: return bad("mobile_limit")
            else -> return bad("mobile_limit")
        }
        val resetAt = when (val v = root["reset_at"]) {
            null, JsonNull -> null
            is JsonNumber -> v.toLongOrNull()?.takeIf { it >= 0 } ?: return bad("reset_at")
            else -> return bad("reset_at")
        }
        val alerted = when (val v = root["alerted_period"]) {
            null, JsonNull -> null
            is JsonString -> date(v.value) ?: return bad("alerted_period")
            else -> return bad("alerted_period")
        }
        val items = (root["days"] as? JsonArray)?.items ?: return bad("days")
        val days = HashMap<LocalDate, MutableMap<NetworkType, UsageBytes>>()
        for ((i, item) in items.withIndex()) {
            val o = item as? JsonObject ?: return bad("days[$i]")
            o.fields.keys.firstOrNull { it !in DAY_KEYS }?.let { return bad("days[$i]: неизвестное поле «$it»") }
            val d = (o["date"] as? JsonString)?.value?.let(::date) ?: return bad("days[$i].date")
            val n = (o["network"] as? JsonString)?.value?.let { v -> NETWORKS.firstOrNull { it.name == v } } ?: return bad("days[$i].network")
            val up = (o["up"] as? JsonNumber)?.toLongOrNull()?.takeIf { it >= 0 } ?: return bad("days[$i].up")
            val down = (o["down"] as? JsonNumber)?.toLongOrNull()?.takeIf { it >= 0 } ?: return bad("days[$i].down")
            val byNetwork = days.getOrPut(d) { HashMap() }
            if (n in byNetwork) return bad("days[$i]: сутки и сеть повторяются")
            byNetwork[n] = UsageBytes(up, down)
        }
        return Outcome.Success(UsageState(UsageSettings(startDay, limit), days, resetAt, alerted))
    }

    private fun date(s: String): LocalDate? = try {
        LocalDate.parse(s)
    } catch (e: DateTimeParseException) {
        null
    }

    private val KEYS = setOf("format", "format_version", "period_start_day", "mobile_limit", "reset_at", "alerted_period", "days")
    private val DAY_KEYS = setOf("date", "network", "up", "down")
}

/** Учёт трафика одной записью (атомарно — от [BlobStore]); не прочитать — исходник в карантин, счёт с нуля. */
class UsageStore(private val blobs: BlobStore, private val quarantine: Quarantine) {
    fun load(): Outcome<UsageState> {
        val bytes = when (val r = blobs.read(KEY)) {
            is Outcome.Failure -> return r
            is Outcome.Success -> r.value ?: return Outcome.Success(UsageState())
        }
        return when (val parsed = UsageCodec.read(String(bytes, Charsets.UTF_8))) {
            is Outcome.Success -> parsed
            is Outcome.Failure -> when (val kept = quarantine.keep("usage", bytes, parsed.errors.first())) {
                is Outcome.Failure -> Outcome.Failure(
                    listOf(
                        Diagnostic.error(DiagCode.STORAGE_CORRUPTED, "учёт трафика не прочитан и не сохранён в карантин")
                            .copy(causes = parsed.diagnostics + kept.diagnostics),
                    ),
                )
                is Outcome.Success -> Outcome.Success(
                    UsageState(),
                    listOf(
                        Diagnostic.warning(DiagCode.STORAGE_CORRUPTED, "учёт трафика не прочитан; исходник сохранён в карантин, счёт — с нуля")
                            .copy(causes = parsed.diagnostics),
                    ),
                )
            }
        }
    }

    fun save(s: UsageState): Outcome<Unit> = blobs.write(KEY, UsageCodec.write(s).toByteArray(Charsets.UTF_8))

    companion object {
        const val KEY: String = "settings/usage"
    }
}

/**
 * Учёт трафика через сервер (D-92): сутки и расчётный период по сетям под
 * туннелем, ручной сброс, порог мобильной сети. Считаются счётчики выхода
 * `proxy` ядра — трафик через сервер, который оператор видит как
 * зарубежный; сайты напрямую не считаются. Оболочка раз в тик передаёт
 * приращение ([record]) и сеть; запись на диск — не чаще
 * [SAVE_EVERY_MILLIS] и при остановке ([flush]).
 */
class UsageService(private val store: UsageStore, private val clock: Clock, private val zone: () -> ZoneId) {
    private val lock = Any()
    private var state: UsageState? = null
    private var dirty = false
    private var savedAt = 0L

    /** Прочитать с диска при первом обращении; не прочитать — счёт с нуля, причина — в [loadNotes]. */
    private fun current(): UsageState = state ?: store.load().let { r ->
        loadNotes = r.diagnostics
        (r.valueOrNull() ?: UsageState()).also { state = it }
    }

    /** Находки чтения с диска — для журнала оболочки. */
    var loadNotes: List<Diagnostic> = emptyList()
        private set

    fun settings(): UsageSettings = synchronized(lock) { current().settings }

    fun setSettings(s: UsageSettings): Outcome<UsageSettings> = synchronized(lock) {
        if (s.periodStartDay !in UsageSettings.DAYS) {
            return Outcome.failure(DiagCode.USAGE_SETTING_INVALID, "день начала периода — от 1 до 31")
        }
        if (s.mobileLimitBytes != null && s.mobileLimitBytes !in 1..UsageSettings.MAX_LIMIT_BYTES) {
            return Outcome.failure(DiagCode.USAGE_SETTING_INVALID, "порог мобильной сети — больше нуля и не больше 1 ПиБ")
        }
        val before = current()
        // Новый порог или период — новое предупреждение: прежнее было о другом.
        val next = before.copy(settings = s, alertedPeriod = if (s == before.settings) before.alertedPeriod else null)
        commit(next).map { s }
    }

    /**
     * Приращение [delta] в сети [network] — в сегодняшние сутки. Порог
     * мобильной сети пройден впервые в этом периоде — [UsageAlert] (и это
     * сразу на диске: после перезапуска не повторится).
     */
    fun record(delta: UsageBytes, network: NetworkType): UsageAlert? = synchronized(lock) {
        if (delta.up < 0 || delta.down < 0) return null
        val now = clock.nowMillis()
        val today = LocalDate.ofInstant(Instant.ofEpochMilli(now), zone())
        val st = current()
        val n = if (network == NetworkType.NONE) NetworkType.OTHER else network
        var next = st
        if (delta.total > 0) {
            val day = st.days[today].orEmpty()
            next = st.copy(days = st.days + (today to (day + (n to (day[n] ?: UsageBytes.ZERO) + delta))))
        }
        val summary = summarize(next, today)
        val limit = next.settings.mobileLimitBytes
        val alert = if (limit != null && summary.mobilePeriodBytes >= limit && next.alertedPeriod != summary.periodStart) {
            next = next.copy(alertedPeriod = summary.periodStart)
            UsageAlert(summary.mobilePeriodBytes, limit, summary.periodStart)
        } else {
            null
        }
        if (next === st) return null
        state = next
        dirty = true
        if (alert != null || now - savedAt >= SAVE_EVERY_MILLIS) save()
        alert
    }

    /** Записать на диск, если есть что: при остановке туннеля. */
    fun flush(): Outcome<Unit> = synchronized(lock) { if (dirty) save() else Outcome.Success(Unit) }

    fun summary(): UsageSummary = synchronized(lock) {
        summarize(current(), LocalDate.ofInstant(Instant.ofEpochMilli(clock.nowMillis()), zone()))
    }

    /** Сброс (пользователь): счёт периода и суток — с нуля с этого момента; прошлые периоды не трогаются. */
    fun reset(): Outcome<Unit> = synchronized(lock) {
        val st = current()
        val today = LocalDate.ofInstant(Instant.ofEpochMilli(clock.nowMillis()), zone())
        val (start, _) = UsagePeriod.of(today, st.settings.periodStartDay)
        commit(st.copy(days = st.days.filterKeys { it < start }, resetAtMillis = clock.nowMillis(), alertedPeriod = null))
    }

    private fun summarize(st: UsageState, today: LocalDate): UsageSummary {
        val (start, end) = UsagePeriod.of(today, st.settings.periodStartDay)
        val period = HashMap<NetworkType, UsageBytes>()
        for ((date, byNetwork) in st.days) {
            if (date < start || date >= end) continue
            for ((n, b) in byNetwork) period[n] = (period[n] ?: UsageBytes.ZERO) + b
        }
        val resetAt = st.resetAtMillis?.takeIf { LocalDate.ofInstant(Instant.ofEpochMilli(it), zone()) >= start }
        return UsageSummary(st.days[today].orEmpty(), period, start, end, resetAt, st.settings)
    }

    private fun commit(next: UsageState): Outcome<Unit> {
        state = next
        dirty = true
        return save()
    }

    /** Сутки старше прошлого периода не нужны: счёт — за сегодня и за период. */
    private fun save(): Outcome<Unit> {
        val st = state ?: return Outcome.Success(Unit)
        val today = LocalDate.ofInstant(Instant.ofEpochMilli(clock.nowMillis()), zone())
        val (start, _) = UsagePeriod.of(today, st.settings.periodStartDay)
        val keepFrom = UsagePeriod.of(start.minusDays(1), st.settings.periodStartDay).first
        val pruned = st.copy(days = st.days.filterKeys { it >= keepFrom })
        val r = store.save(pruned)
        if (r is Outcome.Success) {
            state = pruned
            dirty = false
            savedAt = clock.nowMillis()
        }
        return r
    }

    companion object {
        /** Не чаще раза в минуту: счёт за последнюю минуту при гибели процесса не жалко. */
        const val SAVE_EVERY_MILLIS: Long = 60_000
    }
}
