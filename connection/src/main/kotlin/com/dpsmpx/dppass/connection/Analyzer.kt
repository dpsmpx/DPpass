package com.dpsmpx.dppass.connection

import com.dpsmpx.dppass.core.Clock
import com.dpsmpx.dppass.core.Json
import com.dpsmpx.dppass.core.JsonArray
import com.dpsmpx.dppass.core.JsonBool
import com.dpsmpx.dppass.core.JsonNull
import com.dpsmpx.dppass.core.JsonNumber
import com.dpsmpx.dppass.core.JsonObject
import com.dpsmpx.dppass.core.JsonParseException
import com.dpsmpx.dppass.core.JsonString
import com.dpsmpx.dppass.diagnostics.DiagCode
import com.dpsmpx.dppass.diagnostics.Diagnostic
import com.dpsmpx.dppass.diagnostics.Outcome
import com.dpsmpx.dppass.diagnostics.map
import com.dpsmpx.dppass.engine.ConnNetwork
import com.dpsmpx.dppass.engine.ConnState
import com.dpsmpx.dppass.engine.EngineConnection
import com.dpsmpx.dppass.engine.ProxyEngine
import com.dpsmpx.dppass.engine.RouteKind
import com.dpsmpx.dppass.storage.BlobStore
import com.dpsmpx.dppass.storage.Quarantine

/**
 * Настройки анализатора соединений (D-106). [enabled] — ядро учитывает
 * соединения; выключен — ни учёта, ни нагрузки. [keepUnique] — «Сохранять
 * уникальные соединения»: на диске (зашифровано, D-19) остаётся по строке на
 * каждое уникальное соединение — число подключений и когда было последнее.
 * Оба выключены по умолчанию: адреса назначения — чувствительные данные (T3).
 */
data class AnalyzerSettings(val enabled: Boolean = false, val keepUnique: Boolean = false)

/**
 * Уникальное соединение журнала (D-106): приложение (null — не узнать),
 * адрес — имя сайта, если ядро его распознало, иначе адрес назначения, —
 * порт и сеть.
 */
data class UniqueKey(val app: String?, val host: String, val port: Int, val network: ConnNetwork)

/** Строка журнала: сколько раз было это соединение и когда началось последнее (мс эпохи). */
data class UniqueEntry(val key: UniqueKey, val count: Long, val lastMillis: Long)

/**
 * Владелец соединения — приложение или процесс (D-106): на Android — по UID
 * сокета (Android 10+), на ПК — по сокету в системе. null — не узнать.
 * Зовётся один раз на соединение.
 */
fun interface ConnectionOwners {
    fun owner(c: EngineConnection): String?

    companion object {
        val NONE: ConnectionOwners = ConnectionOwners { null }
    }
}

/**
 * Строка таблицы анализатора (D-106): соединение ядра и что посчитано над
 * снимками. [host] — имя сайта или адрес назначения; [startedAtMillis] —
 * начало по часам устройства; [upRate] и [downRate] — байт в секунду с
 * прошлого снимка, только у открытых (null — снимок первый или соединение
 * закрыто). [hostRecent] — соединений к этому адресу в окне снимка (пять
 * минут), [hostFinished] и [hostFailed] — сколько из них закончилось и
 * сколько прервано.
 */
data class ConnectionRow(
    val connection: EngineConnection,
    val app: String?,
    val host: String,
    val port: Int?,
    val startedAtMillis: Long,
    val upRate: Long?,
    val downRate: Long?,
    val hostRecent: Int,
    val hostFinished: Int,
    val hostFailed: Int,
) {
    val id: Long get() = connection.id
    val state: ConnState get() = connection.state

    /** Надёжность адреса: доля закончившихся штатно, 0…100; null — ни одно ещё не закончилось. */
    val reliability: Int? get() = if (hostFinished == 0) null else (hostFinished - hostFailed) * 100 / hostFinished
}

/**
 * Что показывает анализатор (D-106). [available] — ядро умеет учёт (у
 * фиктивного и незагруженного — нет); [skipped] — не учтено ядром (открытых
 * больше предела); [malformed] — строк снимка не по договору; [uniqueCount]
 * — строк в журнале уникальных; [journalFull] — журнал дошёл до
 * [ConnectionAnalyzer.MAX_UNIQUE] и новых строк не принимает.
 */
data class AnalyzerView(
    val settings: AnalyzerSettings,
    val available: Boolean,
    val rows: List<ConnectionRow>,
    val skipped: Long,
    val malformed: Int,
    val uniqueCount: Int,
    val journalFull: Boolean,
) {
    val open: Int get() = rows.count { it.state == ConnState.OPEN }
    val failed: Int get() = rows.count { it.state == ConnState.FAILED }
    val upRate: Long get() = rows.sumOf { it.upRate ?: 0 }
    val downRate: Long get() = rows.sumOf { it.downRate ?: 0 }
}

object AnalyzerCodec {
    const val FORMAT: String = "dppass.analyzer"
    const val VERSION: Int = 1

    fun write(s: AnalyzerSettings): String = Json.write(
        Json.obj(
            "format" to Json.str(FORMAT),
            "format_version" to Json.num(VERSION),
            "enabled" to JsonBool(s.enabled),
            "keep_unique" to JsonBool(s.keepUnique),
        ),
        pretty = false,
    )

    fun read(text: String): Outcome<AnalyzerSettings> {
        val root = header(text, FORMAT, VERSION, "настройки анализатора") { return it }
        root.fields.keys.firstOrNull { it !in KEYS }?.let { return bad("настройки анализатора: неизвестное поле «$it»") }
        val enabled = (root["enabled"] as? JsonBool)?.value ?: return bad("настройки анализатора: enabled")
        val keep = (root["keep_unique"] as? JsonBool)?.value ?: return bad("настройки анализатора: keep_unique")
        return Outcome.Success(AnalyzerSettings(enabled, keep))
    }

    private val KEYS = setOf("format", "format_version", "enabled", "keep_unique")
}

/**
 * Журнал уникальных соединений (D-106) — формат записи. Только ключ, число
 * и время последнего: ни байтов, ни длительностей, ни адреса источника.
 */
object UniqueJournalCodec {
    const val FORMAT: String = "dppass.connections"
    const val VERSION: Int = 1

    /** Длина имени приложения и адреса в журнале: длиннее — обрезается при записи. */
    const val MAX_TEXT: Int = 255

    fun write(entries: Collection<UniqueEntry>): String = Json.write(
        Json.obj(
            "format" to Json.str(FORMAT),
            "format_version" to Json.num(VERSION),
            "entries" to Json.arr(
                entries.sortedWith(compareBy({ it.key.host }, { it.key.port }, { it.key.network }, { it.key.app.orEmpty() })).map { e ->
                    Json.obj(
                        "app" to (e.key.app?.let(Json::str) ?: JsonNull),
                        "host" to Json.str(e.key.host),
                        "port" to Json.num(e.key.port),
                        "network" to Json.str(e.key.network.name.lowercase()),
                        "count" to Json.num(e.count),
                        "last" to Json.num(e.lastMillis),
                    )
                },
            ),
        ),
        pretty = false,
    )

    fun read(text: String): Outcome<List<UniqueEntry>> {
        val root = header(text, FORMAT, VERSION, "журнал соединений") { return it }
        root.fields.keys.firstOrNull { it !in KEYS }?.let { return bad("журнал соединений: неизвестное поле «$it»") }
        val items = (root["entries"] as? JsonArray)?.items ?: return bad("журнал соединений: entries")
        if (items.size > ConnectionAnalyzer.MAX_UNIQUE) return bad("журнал соединений: строк больше ${ConnectionAnalyzer.MAX_UNIQUE}")
        val out = ArrayList<UniqueEntry>(items.size)
        val keys = HashSet<UniqueKey>()
        for ((i, item) in items.withIndex()) {
            fun no(what: String) = bad<List<UniqueEntry>>("журнал соединений: entries[$i].$what")
            val o = item as? JsonObject ?: return bad("журнал соединений: entries[$i]")
            o.fields.keys.firstOrNull { it !in ENTRY_KEYS }?.let { return no("$it — неизвестное поле") }
            val app = when (val v = o["app"]) {
                null, JsonNull -> null
                is JsonString -> v.value.takeIf { it.isNotEmpty() && it.length <= MAX_TEXT } ?: return no("app")
                else -> return no("app")
            }
            val host = (o["host"] as? JsonString)?.value?.takeIf { it.isNotEmpty() && it.length <= MAX_TEXT } ?: return no("host")
            val port = (o["port"] as? JsonNumber)?.toIntOrNull()?.takeIf { it in 0..65535 } ?: return no("port")
            val network = (o["network"] as? JsonString)?.value?.let { v -> ConnNetwork.entries.firstOrNull { it.name.lowercase() == v } }
                ?: return no("network")
            val count = (o["count"] as? JsonNumber)?.toLongOrNull()?.takeIf { it >= 1 } ?: return no("count")
            val last = (o["last"] as? JsonNumber)?.toLongOrNull()?.takeIf { it >= 0 } ?: return no("last")
            val key = UniqueKey(app, host, port, network)
            if (!keys.add(key)) return bad("журнал соединений: entries[$i] повторяет строку")
            out += UniqueEntry(key, count, last)
        }
        return Outcome.Success(out)
    }

    private val KEYS = setOf("format", "format_version", "entries")
    private val ENTRY_KEYS = setOf("app", "host", "port", "network", "count", "last")
}

private fun <T> bad(what: String): Outcome<T> = Outcome.failure(DiagCode.STORAGE_CORRUPTED, what)

/** Объект JSON с нашим форматом и версией; иначе — [fail] с отказом. */
private inline fun header(text: String, format: String, version: Int, what: String, fail: (Outcome<Nothing>) -> Nothing): JsonObject {
    val root = try {
        Json.parse(text) as? JsonObject
    } catch (e: JsonParseException) {
        null
    } ?: fail(Outcome.failure(DiagCode.STORAGE_CORRUPTED, "$what — не объект JSON"))
    if ((root["format"] as? JsonString)?.value != format || (root["format_version"] as? JsonNumber)?.toIntOrNull() != version) {
        fail(Outcome.failure(DiagCode.FORMAT_VERSION_UNSUPPORTED, "неизвестный формат: $what"))
    }
    return root
}

/**
 * Запись анализатора (настройки или журнал) одной записью [BlobStore]: не
 * прочитать — исходник в карантин и пустое значение, причина — в
 * диагностике (D-06: не подменяем молча).
 */
private class AnalyzerRecord<T>(
    private val blobs: BlobStore,
    private val quarantine: Quarantine,
    private val key: String,
    private val kind: String,
    private val what: String,
    private val empty: T,
    private val read: (String) -> Outcome<T>,
    private val write: (T) -> String,
) {
    fun load(): Outcome<T> {
        val bytes = when (val r = blobs.read(key)) {
            is Outcome.Failure -> return r
            is Outcome.Success -> r.value ?: return Outcome.Success(empty)
        }
        return when (val parsed = read(String(bytes, Charsets.UTF_8))) {
            is Outcome.Success -> parsed
            is Outcome.Failure -> when (val kept = quarantine.keep(kind, bytes, parsed.errors.first())) {
                is Outcome.Failure -> Outcome.Failure(
                    listOf(
                        Diagnostic.error(DiagCode.STORAGE_CORRUPTED, "$what: не прочитано и не сохранено в карантин")
                            .copy(causes = parsed.diagnostics + kept.diagnostics),
                    ),
                )
                is Outcome.Success -> Outcome.Success(
                    empty,
                    listOf(Diagnostic.warning(DiagCode.STORAGE_CORRUPTED, "$what: не прочитано; исходник — в карантине").copy(causes = parsed.diagnostics)),
                )
            }
        }
    }

    fun save(value: T): Outcome<Unit> = blobs.write(key, write(value).toByteArray(Charsets.UTF_8))

    fun delete(): Outcome<Unit> = blobs.delete(key)
}

/**
 * Анализатор соединений (D-106): таблица соединений ядра — открытых и
 * закрытых за пять минут — и журнал уникальных соединений на диске.
 *
 * Живые данные — только в памяти: снимок ядра и посчитанное над ним
 * (скорость с прошлого снимка, частота и надёжность адреса). На диск — лишь
 * журнал уникальных и только при «Сохранять уникальные соединения»:
 * приложение, адрес, порт, сеть, число подключений и время последнего.
 * Соединение попадает в журнал один раз, когда о нём известно главное:
 * выбран маршрут (тогда и имя сайта уже распознано) или оно закончилось.
 * Журнал наполняется, пока его кто-то опрашивает ([poll]): оболочка
 * опрашивает и в фоне, пока работает туннель, — закрытые ядро держит пять
 * минут, и между опросами они не теряются.
 *
 * Запись журнала на диск — не чаще [SAVE_EVERY_MILLIS] и при [flush].
 */
class ConnectionAnalyzer(
    private val engine: ProxyEngine,
    blobs: BlobStore,
    quarantine: Quarantine,
    private val clock: Clock,
    /** Предел строк журнала; меньше [MAX_UNIQUE] — только в тестах. */
    private val maxUnique: Int = MAX_UNIQUE,
) {
    private val settingsRecord = AnalyzerRecord(
        blobs, quarantine, SETTINGS_KEY, "analyzer", "настройки анализатора", AnalyzerSettings(), AnalyzerCodec::read, AnalyzerCodec::write,
    )
    private val journalRecord = AnalyzerRecord<List<UniqueEntry>>(
        blobs, quarantine, JOURNAL_KEY, "connections", "журнал соединений", emptyList(), UniqueJournalCodec::read, UniqueJournalCodec::write,
    )

    private val lock = Any()
    private var settings: AnalyzerSettings? = null
    private var journal: LinkedHashMap<UniqueKey, UniqueEntry>? = null
    private var journalDirty = false
    private var savedAt = 0L
    private var full = false

    /** Что известно о соединении между снимками: по номеру ядра. */
    private class Seen(val startedAt: Long, val owner: String?) {
        var age = -1L
        var up = 0L
        var down = 0L
        var recorded = false
    }

    private val seen = HashMap<Long, Seen>()

    /** Находки чтения с диска — для журнала оболочки. */
    var loadNotes: List<Diagnostic> = emptyList()
        private set

    private fun current(): AnalyzerSettings = settings ?: settingsRecord.load().let { r ->
        loadNotes = loadNotes + r.diagnostics
        (r.valueOrNull() ?: AnalyzerSettings()).also { settings = it }
    }

    private fun entries(): LinkedHashMap<UniqueKey, UniqueEntry> = journal ?: journalRecord.load().let { r ->
        loadNotes = loadNotes + r.diagnostics
        LinkedHashMap<UniqueKey, UniqueEntry>().apply { r.valueOrNull()?.forEach { put(it.key, it) } }.also {
            journal = it
            full = it.size >= maxUnique
        }
    }

    fun settings(): AnalyzerSettings = synchronized(lock) { current() }

    /** Учёт ядра — по сохранённой настройке: при запуске оболочки, когда ядро загружено. */
    fun applyToEngine() = synchronized(lock) { engine.setConnectionTracking(current().enabled) }

    /** Включить или выключить анализатор; выключение стирает учтённое в ядре и в памяти. */
    fun setEnabled(on: Boolean): Outcome<AnalyzerSettings> = synchronized(lock) {
        val next = current().copy(enabled = on)
        settingsRecord.save(next).map {
            settings = next
            engine.setConnectionTracking(on)
            if (!on) {
                seen.clear()
                flushLocked()
            }
            next
        }
    }

    /** «Сохранять уникальные соединения»: выключение перестаёт пополнять журнал, но не стирает его — для этого [clearJournal]. */
    fun setKeepUnique(on: Boolean): Outcome<AnalyzerSettings> = synchronized(lock) {
        val next = current().copy(keepUnique = on)
        settingsRecord.save(next).map {
            settings = next
            if (!on) flushLocked()
            next
        }
    }

    /** Снимок ядра → строки таблицы; при «Сохранять уникальные» — и пополнение журнала. */
    fun poll(owners: ConnectionOwners = ConnectionOwners.NONE): AnalyzerView = synchronized(lock) {
        val st = current()
        val snap = engine.connections()
        if (!st.enabled || snap == null) {
            seen.clear()
            return AnalyzerView(st, snap != null, emptyList(), 0, snap?.malformed ?: 0, journal?.size ?: 0, full)
        }
        val now = clock.nowMillis()
        val byHost = HashMap<String, IntArray>()
        val parts = snap.connections.map { c ->
            val s = seen.getOrPut(c.id) { Seen(startedAt = now - c.ageMillis, owner = owners.owner(c)?.take(UniqueJournalCodec.MAX_TEXT)) }
            val dt = c.ageMillis - s.age
            val rates = if (c.state == ConnState.OPEN && s.age >= 0 && dt > 0) {
                ((c.upBytes - s.up).coerceAtLeast(0) * 1000 / dt) to ((c.downBytes - s.down).coerceAtLeast(0) * 1000 / dt)
            } else {
                null
            }
            s.age = c.ageMillis
            s.up = c.upBytes
            s.down = c.downBytes
            val (host, port) = split(c)
            byHost.getOrPut(host) { IntArray(3) }.let {
                it[0]++
                if (c.state != ConnState.OPEN) it[1]++
                if (c.state == ConnState.FAILED) it[2]++
            }
            if (st.keepUnique && !s.recorded && (c.state != ConnState.OPEN || c.routeKind != RouteKind.NONE)) {
                s.recorded = true
                if (port != null) record(UniqueKey(s.owner, host.take(UniqueJournalCodec.MAX_TEXT), port, c.network), s.startedAt)
            }
            Triple(c, s, Triple(host, port, rates))
        }
        val ids = snap.connections.mapTo(HashSet()) { it.id }
        seen.keys.retainAll(ids)
        val rows = parts.map { (c, s, rest) ->
            val (host, port, rates) = rest
            val h = byHost.getValue(host)
            ConnectionRow(c, s.owner, host, port, s.startedAt, rates?.first, rates?.second, h[0], h[1], h[2])
        }
        if (journalDirty && now - savedAt >= SAVE_EVERY_MILLIS) saveJournal(now)
        AnalyzerView(st, true, rows, snap.skipped, snap.malformed, journal?.size ?: 0, full)
    }

    private fun record(key: UniqueKey, startedAt: Long) {
        val map = entries()
        val prev = map[key]
        if (prev == null && map.size >= maxUnique) {
            full = true
            return
        }
        map[key] = UniqueEntry(key, (prev?.count ?: 0) + 1, maxOf(prev?.lastMillis ?: 0, startedAt))
        journalDirty = true
    }

    /** Журнал уникальных соединений, последние первыми. */
    fun unique(): List<UniqueEntry> = synchronized(lock) { entries().values.sortedByDescending { it.lastMillis } }

    /**
     * «Очистить журнал подключений»: с диска и из памяти. Соединения на
     * экране, уже записанные, заново не попадают; ещё не записанные — как новые.
     */
    fun clearJournal(): Outcome<Unit> = synchronized(lock) {
        journalRecord.delete().map {
            journal = LinkedHashMap()
            journalDirty = false
            full = false
        }
    }

    /** Записать журнал, если есть что: при остановке туннеля и выходе. */
    fun flush(): Outcome<Unit> = synchronized(lock) { flushLocked() }

    private fun flushLocked(): Outcome<Unit> = if (journalDirty) saveJournal(clock.nowMillis()) else Outcome.Success(Unit)

    private fun saveJournal(now: Long): Outcome<Unit> {
        val map = journal ?: return Outcome.Success(Unit)
        return journalRecord.save(map.values.toList()).map {
            journalDirty = false
            savedAt = now
        }
    }

    companion object {
        const val SETTINGS_KEY: String = "settings/analyzer"
        const val JOURNAL_KEY: String = "connections/unique"

        /** Журнал пишется на диск не чаще раза в минуту. */
        const val SAVE_EVERY_MILLIS: Long = 60_000

        /** Строк журнала не больше: дальше новые не принимаются, и это видно ([AnalyzerView.journalFull]). */
        const val MAX_UNIQUE: Int = 50_000

        /** Адрес и порт соединения: имя сайта, если распознано, иначе адрес назначения. */
        fun split(c: EngineConnection): Pair<String, Int?> {
            val t = c.target
            val i = t.lastIndexOf(':')
            val port = if (i > 0) t.substring(i + 1).toIntOrNull()?.takeIf { it in 0..65535 } else null
            val addr = (if (port != null) t.substring(0, i) else t).removePrefix("[").removeSuffix("]")
            return c.domain.ifEmpty { addr } to port
        }
    }
}
