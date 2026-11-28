package com.dpsmpx.dppass.app

import java.io.File
import java.nio.file.Files
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class DptsReportArchiveTest {
    private fun withArchive(block: (File, DptsReportArchive) -> Unit) {
        val directory = Files.createTempDirectory("dpts-report-test").toFile()
        try { block(directory, DptsReportArchive(directory)) } finally { directory.deleteRecursively() }
    }

    @Test fun retainsTextAndCsvAcrossInstancesAndDeletesOnlySelectedSnapshot() = withArchive { dir, archive ->
        assertTrue(archive.save("Отчёт №1", "method,outcome\r\nplain,ok\r\n", 1))
        assertTrue(archive.save("Second report", null, 2))
        val reopened = DptsReportArchive(dir)
        val records = requireNotNull(reopened.list())
        assertEquals(listOf("Second report", "Отчёт №1"), records.map { it.report })
        assertEquals("method,outcome\r\nplain,ok\r\n", records[1].csv)
        assertFalse(reopened.delete(records[1].copy(report = "different")))
        assertTrue(reopened.delete(records[1]))
        assertEquals(listOf(records[0]), reopened.list())
    }

    @Test fun fullArchiveNeverEvictsAndOversizedFieldsAreRefused() = withArchive { _, archive ->
        assertFalse(archive.save("", null))
        assertFalse(archive.save("я".repeat(DptsReportArchive.MAX_FIELD_BYTES), null))
        assertFalse(archive.save("report", "x".repeat(DptsReportArchive.MAX_FIELD_BYTES + 1)))
        repeat(DptsReportArchive.MAX_RECORDS) { assertTrue(archive.save("report $it", null, it + 1L)) }
        val before = requireNotNull(archive.list())
        assertFalse(archive.save("extra", null))
        assertEquals(before, archive.list())
        assertTrue(archive.delete(before.last()))
        assertTrue(archive.save("extra", null))
    }

    @Test fun corruptAndForeignRecordsCannotBeOpenedOrDeletedAsValid() = withArchive { dir, archive ->
        assertTrue(archive.save("valid", "csv", 1))
        val record = requireNotNull(archive.list()).single()
        val file = File(dir, record.id + ".report")
        file.writeBytes(file.readBytes() + byteArrayOf(0))
        assertTrue(requireNotNull(archive.list()).isEmpty())
        assertFalse(archive.delete(record))
        assertTrue(file.exists())
        val unrelated = File(dir, "subscription.json").apply { writeText("keep") }
        assertFalse(archive.delete(record.copy(id = "../subscription")))
        assertTrue(unrelated.exists())
    }
}
