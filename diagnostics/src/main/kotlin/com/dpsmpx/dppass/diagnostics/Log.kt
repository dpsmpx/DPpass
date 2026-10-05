package com.dpsmpx.dppass.diagnostics

/**
 * Структурный журнал: событие — имя и поля, а не склеенная строка.
 *
 * Каждое строковое поле проходит [Redactor] **до** попадания в
 * приёмник; [Secret] превращается в метку; явно безопасное значение
 * оборачивается в [Safe] (константы, имена шагов, коды). Сырые строки
 * ядра и сети сюда приходят только через поля — и тоже редактируются.
 */
data class LogEvent(
    val timestampMillis: Long,
    val severity: Severity,
    val component: String,
    val event: String,
    val fields: Map<String, String>,
) {
    fun render(): String = buildString {
        append(timestampMillis).append(' ').append(severity.name).append(' ')
        append(component).append(' ').append(event)
        for ((k, v) in fields) append(' ').append(k).append('=').append(v)
    }
}

/** Значение, заведомо не содержащее секретов: не редактируется. */
@JvmInline
value class Safe(val value: String)

fun interface LogSink {
    fun emit(event: LogEvent)
}

/** Приёмник, который помнит последние события: из них строится локальный отчёт. */
interface LogHistory {
    fun snapshot(): List<LogEvent>
}

/** Кольцевой буфер в памяти: источник для локального отчёта. */
class MemoryLogSink(private val capacity: Int = 512) : LogSink, LogHistory {
    private val buffer = ArrayDeque<LogEvent>()

    @Synchronized
    override fun emit(event: LogEvent) {
        if (buffer.size == capacity) buffer.removeFirst()
        buffer.addLast(event)
    }

    @Synchronized
    override fun snapshot(): List<LogEvent> = buffer.toList()
}

/**
 * Одно событие — в несколько приёмников (на устройстве: кольцо для
 * отчёта и файл журнала, D-26). История — у первого приёмника, который
 * её помнит.
 */
class TeeLogSink(private val sinks: List<LogSink>) : LogSink, LogHistory {
    constructor(vararg sinks: LogSink) : this(sinks.toList())

    override fun emit(event: LogEvent) {
        for (s in sinks) s.emit(event)
    }

    override fun snapshot(): List<LogEvent> = sinks.firstNotNullOfOrNull { it as? LogHistory }?.snapshot().orEmpty()
}

class Logger(
    private val component: String,
    private val sink: LogSink,
    private val nowMillis: () -> Long,
    private val redactor: Redactor = Redactor(),
) {
    fun info(event: String, vararg fields: Pair<String, Any?>) = log(Severity.INFO, event, fields)
    fun warning(event: String, vararg fields: Pair<String, Any?>) = log(Severity.WARNING, event, fields)
    fun error(event: String, vararg fields: Pair<String, Any?>) = log(Severity.ERROR, event, fields)

    /**
     * Диагностика и вся цепочка её причин (D-22): «не активировано» без
     * «ядро отвергло» и без текста ядра ничего не объясняет. Каждая
     * причина — своё событие `cause` с глубиной; сводка исключения —
     * полями `error_type`/`error`. Глубина и число причин ограничены.
     */
    fun diagnostic(d: Diagnostic) {
        log(d.severity, "diagnostic", fieldsOf(d, null))
        var budget = MAX_CAUSES
        fun causes(of: Diagnostic, depth: Int) {
            for (c in of.causes) {
                if (budget-- <= 0 || depth > MAX_CAUSE_DEPTH) return
                log(c.severity, "cause", fieldsOf(c, depth))
                causes(c, depth + 1)
            }
        }
        causes(d, 1)
    }

    private fun fieldsOf(d: Diagnostic, depth: Int?): Array<Pair<String, Any?>> = listOfNotNull(
        depth?.let { "depth" to it },
        "code" to Safe(d.code.name),
        // Без пути — без поля: «path=null» в журнале устройства читается как ошибка.
        d.path?.let { "path" to it },
        "message" to d.message,
        d.error?.let { "error_type" to it.type },
        d.error?.message?.let { "error" to it },
    ).toTypedArray()

    private fun log(severity: Severity, event: String, fields: Array<out Pair<String, Any?>>) {
        val rendered = LinkedHashMap<String, String>(fields.size)
        for ((key, value) in fields) {
            rendered[key] = when (value) {
                null -> "null"
                is Secret -> Secret.REDACTED
                is Safe -> value.value
                is Number, is Boolean, is Enum<*> -> value.toString()
                else -> redactor.redact(value.toString())
            }
        }
        sink.emit(LogEvent(nowMillis(), severity, component, event, rendered))
    }

    private companion object {
        const val MAX_CAUSE_DEPTH = 8
        const val MAX_CAUSES = 32
    }
}
