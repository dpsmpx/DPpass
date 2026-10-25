package com.dpsmpx.dppass.diagnostics

import java.io.File
import java.io.FileOutputStream
import java.io.IOException
import java.io.RandomAccessFile
import java.time.Instant
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executor
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger

/**
 * Журнал в файле (D-26): строки событий [Logger] пишутся **в фоне** —
 * вызывающий только ставит строку в очередь. Очередь ограничена: при
 * переполнении строка не ждёт, а теряется, и в файл потом попадает
 * отметка, сколько потеряно.
 *
 * Раскладка каталога [dir] (сеанс — один запуск процесса):
 * - `current.log` — текущая часть сеанса; больше [partBytes] — она
 *   становится `current.1.log`, а прежняя `current.1.log` удаляется;
 * - `current.head.log` — первые [headBytes] сеанса, сохранённые при
 *   первой смене части: в начале — условия запуска;
 * - `previous*.log` — то же для прошлого сеанса ([startSession] переносит).
 *
 * На диске не больше `2 × partBytes + headBytes` на сеанс. Секретов в
 * строках нет: событие уже отредактировано [Logger] (D-11).
 */
class FileLogSink(
    private val dir: File,
    private val nowMillis: () -> Long,
    private val executor: Executor = writerThread(),
    private val partBytes: Long = PART_BYTES,
    private val headBytes: Int = HEAD_BYTES,
    private val queueLimit: Int = QUEUE_LIMIT,
) : LogSink {
    private val pending = AtomicInteger()
    private val dropped = AtomicInteger()

    // Ниже — только из потока записи (executor исполняет задачи по одной).
    private var out: FileOutputStream? = null
    private var size = 0L
    private var part = 1
    private var closed = false

    /** Сбой записи (диск полон, каталог недоступен): дальше файл не пишется. */
    @Volatile
    var failure: String? = null
        private set

    /**
     * Начать сеанс: прошлый сеанс — в `previous*`, позапрошлый удаляется;
     * [header] — первые строки нового сеанса (условия запуска).
     */
    fun startSession(header: List<String>) {
        executor.execute {
            try {
                dir.mkdirs()
                for (name in SESSION_FILES) {
                    val prev = File(dir, "previous" + name.removePrefix("current"))
                    prev.delete()
                    File(dir, name).takeIf { it.isFile }?.renameTo(prev)
                }
                open()
                for (line in header) write(line)
            } catch (e: IOException) {
                fail(e)
            }
        }
    }

    override fun emit(event: LogEvent) {
        if (pending.incrementAndGet() > queueLimit) {
            pending.decrementAndGet()
            dropped.incrementAndGet()
            return
        }
        val line = format(event)
        executor.execute {
            try {
                write(line)
                // Отметка о потерянном — там, где очередь опустела: потеряны строки
                // после тех, что в ней стояли.
                if (pending.get() == 1) {
                    val lost = dropped.getAndSet(0)
                    if (lost > 0) write("${stamp(nowMillis())} WARNING log queue_overflow lost=$lost")
                }
            } catch (e: IOException) {
                fail(e)
            } finally {
                pending.decrementAndGet()
            }
        }
    }

    /**
     * Дождаться, пока очередь допишется (перед копией в буфер обмена и
     * при падении). Ложь — не уложились в [timeoutMillis].
     */
    fun flush(timeoutMillis: Long): Boolean {
        val done = CountDownLatch(1)
        executor.execute { done.countDown() }
        return done.await(timeoutMillis, TimeUnit.MILLISECONDS)
    }

    /** Закрыть файл (выключение журнала); новые строки после этого не пишутся. */
    fun close() {
        executor.execute {
            try {
                out?.close()
            } catch (_: IOException) {
                // Закрытие после сбоя записи: сообщать уже некуда.
            }
            out = null
            closed = true
        }
    }

    private fun open() {
        val f = File(dir, CURRENT)
        out = FileOutputStream(f, true)
        size = f.length()
    }

    private fun write(line: String) {
        if (failure != null || closed) return
        if (out == null) open()
        val bytes = (line + "\n").toByteArray(Charsets.UTF_8)
        // Одна смена части на строку: строка длиннее части пишется целиком.
        if (size > 0 && size + bytes.size > partBytes) rotate()
        append(bytes)
    }

    /** Без буфера: строка уходит в ОС сразу и переживает гибель процесса. */
    private fun append(bytes: ByteArray) {
        out!!.write(bytes)
        size += bytes.size
    }

    private fun rotate() {
        out?.close()
        val current = File(dir, CURRENT)
        val head = File(dir, HEAD)
        if (!head.isFile) {
            val n = minOf(headBytes.toLong(), current.length()).toInt()
            val buf = ByteArray(n)
            RandomAccessFile(current, "r").use { it.readFully(buf) }
            head.writeBytes(buf)
        }
        val older = File(dir, PART_1)
        older.delete()
        if (!current.renameTo(older)) throw IOException("не переименован ${current.name}")
        part++
        open()
        append("${stamp(nowMillis())} INFO log continued part=$part\n".toByteArray(Charsets.UTF_8))
    }

    private fun fail(e: IOException) {
        failure = e.message ?: e.javaClass.name
        try {
            out?.close()
        } catch (_: IOException) {
            // Закрытие после сбоя записи: сообщать уже некуда.
        }
        out = null
    }

    companion object {
        const val CURRENT: String = "current.log"
        const val PART_1: String = "current.1.log"
        const val HEAD: String = "current.head.log"
        const val PREVIOUS: String = "previous.log"
        const val PREVIOUS_PART_1: String = "previous.1.log"
        const val PREVIOUS_HEAD: String = "previous.head.log"
        private val SESSION_FILES = listOf(CURRENT, PART_1, HEAD)

        const val PART_BYTES: Long = 1L shl 20
        const val HEAD_BYTES: Int = 32 * 1024
        const val QUEUE_LIMIT: Int = 4096

        /** Строка файла: время UTC ISO-8601, затем событие как в отчёте. */
        fun format(e: LogEvent): String = buildString {
            append(stamp(e.timestampMillis)).append(' ').append(e.severity.name).append(' ')
            append(e.component).append(' ').append(e.event)
            for ((k, v) in e.fields) append(' ').append(k).append('=').append(v)
        }

        fun stamp(millis: Long): String = Instant.ofEpochMilli(millis).toString()

        private fun writerThread(): Executor = Executors.newSingleThreadExecutor { r ->
            Thread(r, "dppass-log").apply { isDaemon = true }
        }
    }
}

/**
 * Запись о падении (D-26): тип, отредактированное сообщение и кадры
 * стека каждой причины. Пишется синхронно и мимо выключателя журнала:
 * после неё процесс умирает, писать будет некому.
 */
object CrashRecord {
    const val FILE: String = "crash.log"
    private const val MAX_CAUSES = 8
    private const val MAX_FRAMES = 48

    fun render(thread: String, error: Throwable, nowMillis: Long, redactor: Redactor = Redactor()): String = buildString {
        append(FileLogSink.stamp(nowMillis)).append(" FATAL поток=").append(redactor.redact(thread)).append('\n')
        var t: Throwable? = error
        var depth = 0
        val seen = HashSet<Throwable>()
        while (t != null && depth < MAX_CAUSES && seen.add(t)) {
            if (depth > 0) append("причина: ")
            append(t.javaClass.name)
            t.message?.let { append(": ").append(redactor.redact(it)) }
            append('\n')
            val frames = t.stackTrace
            for (f in frames.take(MAX_FRAMES)) append("    at ").append(f.toString()).append('\n')
            if (frames.size > MAX_FRAMES) append("    … ещё ").append(frames.size - MAX_FRAMES).append(" кадров\n")
            t = t.cause
            depth++
        }
    }

    /** Дописать запись в [dir]/crash.log; сбой записи молча проглатывается — процесс и так падает. */
    fun append(dir: File, text: String) {
        try {
            dir.mkdirs()
            FileOutputStream(File(dir, FILE), true).use { it.write((text + "\n").toByteArray(Charsets.UTF_8)) }
        } catch (_: IOException) {
            // Падение уже идёт: другого места для записи нет.
        }
    }
}

/**
 * Текст журнала для буфера обмена (D-26): единственный путь журнала
 * наружу. Записи о падении, начало сеанса и хвост — в пределах
 * [maxChars]; середина длинного сеанса заменяется отметкой. Всё ещё раз
 * проходит [Redactor] уровня `STRICT` — как отчёт, который отдают
 * кому-то (без IP и имён хостов).
 *
 * [memory] — события этого запуска из кольца памяти, когда журнал в файл
 * выключен (D-54): тогда текущий сеанс — они, а не файл. Файла этого
 * запуска нет, а в каталоге — разве что запуск, когда журнал был включён.
 * [header] — строки начала сеанса (версия, условия запуска): у файла они
 * записаны при открытии, у памяти — только здесь (D-87).
 */
object LogExport {
    const val MAX_CHARS: Int = 120_000
    const val HEAD_CHARS: Int = 20_000
    private const val PREVIOUS_TAIL_CHARS = 20_000

    fun text(
        dir: File,
        title: String,
        maxChars: Int = MAX_CHARS,
        headChars: Int = HEAD_CHARS,
        memory: List<LogEvent>? = null,
        header: List<String> = emptyList(),
    ): String {
        val crash = read(File(dir, CrashRecord.FILE))
        val session = if (memory != null) memoryText(memory, header) else sessionText(dir, FileLogSink.CURRENT, FileLogSink.PART_1, FileLogSink.HEAD)
        val raw = buildString {
            append("=== ").append(title).append(" ===\n")
            if (crash.isNotEmpty()) {
                append("\n=== Падение ===\n").append(crash)
                val previous = sessionText(dir, FileLogSink.PREVIOUS, FileLogSink.PREVIOUS_PART_1, FileLogSink.PREVIOUS_HEAD)
                if (previous.isNotEmpty()) {
                    append("\n=== Прошлый сеанс (хвост) ===\n").append(tail(previous, PREVIOUS_TAIL_CHARS))
                }
            }
            append("\n=== Текущий сеанс ===\n")
            append(session.ifEmpty { "(журнал пуст или выключен)\n" })
        }
        val strict = Redactor(Redactor.Level.STRICT)
        return bounded(raw.lineSequence().joinToString("\n") { redactLine(it, strict) }, maxChars, headChars)
    }

    /**
     * Время в начале строки не редактируется: `16:47:36` для `STRICT` —
     * похоже на адрес IPv6. Остальное — как есть через [redactor].
     */
    private fun redactLine(line: String, redactor: Redactor): String {
        val stamp = STAMP.find(line) ?: return redactor.redact(line)
        return stamp.value + redactor.redact(line.substring(stamp.value.length))
    }

    private val STAMP = Regex("""^\d{4}-\d{2}-\d{2}T[0-9:.]+Z """)

    /** Удалить записи о падении — после того как они ушли в буфер обмена. */
    fun clearCrash(dir: File) {
        File(dir, CrashRecord.FILE).delete()
    }

    /**
     * Не длиннее [maxChars]: начало [headChars] и хвост, по границам
     * строк, с отметкой, сколько пропущено. Короткий текст — как есть.
     */
    fun bounded(text: String, maxChars: Int, headChars: Int): String {
        require(maxChars >= 1000 && headChars < maxChars / 2) { "предел буфера слишком мал" }
        if (text.length <= maxChars) return text
        val note = "\n\n… пропущено %d символов середины журнала (всего %d) …\n\n"
        val budget = maxChars - note.length - 24
        val headEnd = text.lastIndexOf('\n', minOf(headChars, budget)).let { if (it <= 0) minOf(headChars, budget) else it + 1 }
        var tailStart = text.length - (budget - headEnd)
        val nl = text.indexOf('\n', tailStart)
        if (nl in tailStart until text.length - 1) tailStart = nl + 1
        return text.substring(0, headEnd) + note.format(tailStart - headEnd, text.length) + text.substring(tailStart)
    }

    private fun sessionText(dir: File, current: String, part1: String, head: String): String {
        val headText = read(File(dir, head))
        val tailText = read(File(dir, part1)) + read(File(dir, current))
        if (headText.isEmpty()) return tailText
        return headText + (if (headText.endsWith("\n")) "" else "\n") + "… (начало сеанса выше, дальше — последние части) …\n" + tailText
    }

    /** Строки кольца — как строки файла ([FileLogSink.format]), с пометкой, откуда они. */
    private fun memoryText(events: List<LogEvent>, header: List<String>): String {
        if (events.isEmpty()) return ""
        val note = "(журнал на телефоне выключен — события этого запуска из памяти)\n"
        val head = header.joinToString("") { it + "\n" }
        return events.joinToString("\n", prefix = note + head, postfix = "\n") { FileLogSink.format(it) }
    }

    private fun tail(text: String, chars: Int): String {
        if (text.length <= chars) return text
        val start = text.indexOf('\n', text.length - chars).let { if (it < 0) text.length - chars else it + 1 }
        return "…\n" + text.substring(start)
    }

    private fun read(f: File): String = try {
        if (f.isFile) f.readText(Charsets.UTF_8) else ""
    } catch (_: IOException) {
        ""
    }
}
