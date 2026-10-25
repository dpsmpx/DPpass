package com.dpsmpx.dppass.diagnostics

import java.io.File
import java.nio.file.Files
import java.util.concurrent.Executor
import java.util.concurrent.LinkedBlockingQueue
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

private const val UUID = "00000000-0000-4000-8000-000000000001"

private fun tempDir(): File = Files.createTempDirectory("dppass-log").toFile()

private fun event(n: Int, text: String = "x") = LogEvent(1_759_590_000_000L + n, Severity.INFO, "core", "e$n", mapOf("v" to text))

/** Задачи копятся и выполняются по команде: «фон», который тест держит в руках. */
private class ManualExecutor : Executor {
    val tasks = LinkedBlockingQueue<Runnable>()
    override fun execute(command: Runnable) {
        tasks.add(command)
    }

    fun runAll() {
        while (true) (tasks.poll() ?: return).run()
    }
}

class FileLogSinkTest {
    private val dir = tempDir()

    @AfterTest
    fun cleanup() {
        dir.deleteRecursively()
    }

    @Test
    fun writesInBackgroundInOrder() {
        val sink = FileLogSink(dir, { 0L })
        sink.startSession(listOf("header line"))
        val logger = Logger("core", sink, { 1_759_590_000_000L })
        repeat(200) { logger.info("step", "n" to it) }
        assertTrue(sink.flush(5_000), "очередь не дописалась")
        val lines = File(dir, FileLogSink.CURRENT).readLines()
        assertEquals("header line", lines.first())
        assertEquals((0 until 200).map { "n=$it" }, lines.drop(1).map { it.substringAfterLast(' ') })
        assertTrue(lines[1].startsWith("2025-10-04T"), lines[1])
        assertNull(sink.failure)
    }

    @Test
    fun callerDoesNotWaitAndOverflowIsCounted() {
        val bg = ManualExecutor()
        val sink = FileLogSink(dir, { 0L }, bg, queueLimit = 10)
        repeat(25) { sink.emit(event(it)) }
        // Ничего ещё не записано: вызывающий только поставил строки в очередь.
        assertFalse(File(dir, FileLogSink.CURRENT).exists())
        bg.runAll()
        sink.emit(event(99))
        bg.runAll()
        val lines = File(dir, FileLogSink.CURRENT).readLines()
        assertEquals(12, lines.size, lines.joinToString("\n"))
        assertTrue(lines[10].endsWith("queue_overflow lost=15"), lines[10])
        assertTrue(lines[11].contains(" e99 "))
    }

    @Test
    fun partsAreBoundedAndSessionStartIsKept() {
        val sink = FileLogSink(dir, { 0L }, { it.run() }, partBytes = 4_000, headBytes = 500)
        sink.startSession(listOf("START conditions"))
        repeat(1_000) { sink.emit(event(it, "y".repeat(40))) }
        val names = dir.list()!!.toSortedSet()
        assertEquals(sortedSetOf(FileLogSink.CURRENT, FileLogSink.PART_1, FileLogSink.HEAD), names)
        for (n in names) assertTrue(File(dir, n).length() <= 4_000 + 200, "$n: ${File(dir, n).length()}")
        val head = File(dir, FileLogSink.HEAD).readText()
        assertTrue(head.startsWith("START conditions"), "начало сеанса сохранено")
        assertTrue(head.length <= 500)
        assertTrue(File(dir, FileLogSink.CURRENT).readLines().first().contains("log continued part="))
        assertTrue(File(dir, FileLogSink.CURRENT).readText().contains(" e999 "), "хвост — последние строки")
    }

    @Test
    fun newSessionMovesPreviousOne() {
        val first = FileLogSink(dir, { 0L }, { it.run() })
        first.startSession(listOf("first run"))
        first.emit(event(1))
        first.close()
        val second = FileLogSink(dir, { 0L }, { it.run() })
        second.startSession(listOf("second run"))
        assertEquals("first run", File(dir, FileLogSink.PREVIOUS).readLines().first())
        assertEquals("second run", File(dir, FileLogSink.CURRENT).readLines().single())
        val third = FileLogSink(dir, { 0L }, { it.run() })
        third.startSession(listOf("third run"))
        assertEquals("second run", File(dir, FileLogSink.PREVIOUS).readLines().first(), "позапрошлый сеанс удалён")
    }

    @Test
    fun closedSinkWritesNothing() {
        val sink = FileLogSink(dir, { 0L }, { it.run() })
        sink.emit(event(1))
        sink.close()
        sink.emit(event(2))
        assertEquals(1, File(dir, FileLogSink.CURRENT).readLines().size)
    }

    @Test
    fun teeKeepsHistoryForReport() {
        val memory = MemoryLogSink()
        val file = FileLogSink(dir, { 0L }, { it.run() })
        val tee = TeeLogSink(memory, file)
        tee.emit(event(7))
        assertEquals(listOf("e7"), tee.snapshot().map { it.event })
        assertTrue(File(dir, FileLogSink.CURRENT).readText().contains(" e7 "))
    }
}

class LogExportTest {
    private val dir = tempDir()

    @AfterTest
    fun cleanup() {
        dir.deleteRecursively()
    }

    @Test
    fun strictRedactionKeepsTimestamps() {
        val sink = FileLogSink(dir, { 0L }, { it.run() })
        val logger = Logger("core", sink, { 1_759_590_000_123L })
        logger.info("connect", "server" to "203.0.113.10", "url" to "https://sub.example.com/token/abc", "v6" to "2001:db8::1")
        val text = LogExport.text(dir, "DPpass")
        assertTrue("2025-10-04T15:00:00.123Z INFO core connect" in text, text)
        assertFalse("203.0.113.10" in text, "IP — только в STRICT-виде: $text")
        assertFalse("2001:db8::1" in text, text)
        assertFalse("sub.example.com" in text, text)
        assertTrue(text.startsWith("=== DPpass ==="))
    }

    @Test
    fun crashRecordIsIncludedAndCleared() {
        val previous = FileLogSink(dir, { 0L }, { it.run() })
        previous.startSession(listOf("old session"))
        previous.emit(event(1, "before crash"))
        CrashRecord.append(dir, CrashRecord.render("main", IllegalStateException("boom"), 0L))
        val now = FileLogSink(dir, { 0L }, { it.run() })
        now.startSession(listOf("new session"))
        val text = LogExport.text(dir, "DPpass")
        val crash = text.indexOf("=== Падение ===")
        val prev = text.indexOf("=== Прошлый сеанс (хвост) ===")
        val cur = text.indexOf("=== Текущий сеанс ===")
        assertTrue(crash in 0 until prev && prev < cur, text)
        assertTrue("java.lang.IllegalStateException: boom" in text)
        assertTrue("before crash" in text)
        LogExport.clearCrash(dir)
        assertFalse("=== Падение ===" in LogExport.text(dir, "DPpass"))
    }

    @Test
    fun emptyLogSaysSo() {
        assertTrue("(журнал пуст или выключен)" in LogExport.text(dir, "DPpass"))
        assertTrue("(журнал пуст или выключен)" in LogExport.text(dir, "DPpass", memory = emptyList()))
    }

    // D-54: журнал в файл выключен — кнопка копирует события этого запуска
    // из памяти (как локальный отчёт), а не пустоту или файл прошлого запуска.
    @Test
    fun logOffCopiesThisRunFromMemory() {
        val earlier = FileLogSink(dir, { 0L }, { it.run() })
        earlier.startSession(listOf("earlier run"))
        CrashRecord.append(dir, CrashRecord.render("main", IllegalStateException("boom"), 0L))
        val run = listOf(event(1, "engine loaded"), event(2, "203.0.113.10"))
        val header = "1970-01-01T00:00:00.000Z INFO app session_start version=0.7.39-dev api=36 abis=arm64-v8a debuggable=true"
        val text = LogExport.text(dir, "DPpass", memory = run, header = listOf(header))
        val session = text.substringAfter("=== Текущий сеанс ===\n")
        assertTrue(session.startsWith("(журнал на телефоне выключен — события этого запуска из памяти)\n"), text)
        // D-87: версия и условия запуска — и в копии из памяти, первыми.
        assertTrue(session.lines()[1].contains("session_start version=0.7.39-dev api=36"), text)
        assertTrue("${FileLogSink.format(run[0])}\n" in session, text)
        assertTrue(" e2 " in session, text)
        assertFalse("203.0.113.10" in text, "IP — только в STRICT-виде: $text")
        assertFalse("earlier run" in session, "файл прошлого запуска — не текущий сеанс: $text")
        assertTrue("java.lang.IllegalStateException: boom" in text, "падение — как прежде")
    }

    @Test
    fun longTextKeepsHeadAndTail() {
        val text = (0 until 20_000).joinToString("\n") { "line $it" }
        val out = LogExport.bounded(text, 10_000, 2_000)
        assertTrue(out.length <= 10_000, "${out.length}")
        assertTrue(out.startsWith("line 0\n"))
        assertTrue(out.endsWith("line 19999"))
        assertTrue("пропущено" in out)
        assertTrue(out.substringBefore("\n\n…").endsWith("\n"), "начало обрезано по строке")
        assertEquals(text.take(100), LogExport.bounded(text.take(100), 10_000, 2_000))
    }

    @Test
    fun rotatedSessionShowsStartAndTail() {
        val sink = FileLogSink(dir, { 0L }, { it.run() }, partBytes = 4_000, headBytes = 300)
        sink.startSession(listOf("START"))
        repeat(1_000) { sink.emit(event(it)) }
        val text = LogExport.text(dir, "DPpass")
        assertTrue(text.substringAfter("=== Текущий сеанс ===\n").startsWith("START"))
        assertTrue("начало сеанса выше" in text)
        assertTrue(" e999 " in text)
    }
}

class CrashRecordTest {
    @Test
    fun messageIsRedactedAndFramesArePresent() {
        val error = RuntimeException("activation failed for vless://$UUID@203.0.113.10:443", IllegalArgumentException("id=$UUID"))
        val text = CrashRecord.render("dppass-io", error, 1_759_590_000_000L)
        assertFalse(UUID in text, text)
        assertTrue(text.startsWith("2025-10-04T15:00:00Z FATAL поток=dppass-io"), text)
        assertTrue("java.lang.RuntimeException: activation failed" in text)
        assertTrue("причина: java.lang.IllegalArgumentException" in text)
        assertTrue("    at com.dpsmpx.dppass.diagnostics.CrashRecordTest" in text, text)
    }

    @Test
    fun causeCycleDoesNotHang() {
        val a = RuntimeException("a")
        val b = RuntimeException("b", a)
        a.initCause(b)
        val text = CrashRecord.render("t", a, 0L)
        assertEquals(2, Regex("RuntimeException").findAll(text).count())
    }
}
