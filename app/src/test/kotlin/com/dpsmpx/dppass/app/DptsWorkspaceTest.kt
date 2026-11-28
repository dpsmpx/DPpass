package com.dpsmpx.dppass.app

import com.dpsmpx.dppass.engine.xray.DptsScript
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class DptsWorkspaceTest {
    @Test fun utf8FilesRoundTripWithoutCompilingDrafts() {
        val text = "dpts 1\r\nname Тест\r\n# незаконченный черновик"
        assertEquals(text, DptsWorkspace.read(text.byteInputStream()))
        assertEquals(text, DptsWorkspace.read(("\uFEFF" + text).byteInputStream()))
        assertEquals("", DptsWorkspace.read("".byteInputStream()))
        assertNull(DptsWorkspace.read(byteArrayOf(0xC3.toByte(), 0x28).inputStream()))
        assertNull(DptsWorkspace.read("bad\u0000text".byteInputStream()))
        assertNull(DptsWorkspace.read("a".repeat(DptsScript.MAX_SOURCE_LENGTH + 1).byteInputStream()))
        val max = "я".repeat(DptsScript.MAX_SOURCE_LENGTH)
        assertEquals(max, DptsWorkspace.read(max.byteInputStream()))
    }

    @Test fun previewShowsExpandedOrderAndBudgetWithoutRunning() {
        val plan = DptsScript.compile("dpts 1\nhost example.org\nhttps protocols=h1,h2 ips=1 attempts=1")
        val preview = DptsWorkspace.preview(plan)
        assertTrue(preview.contains("Probes: 2"))
        assertTrue(preview.contains("Probe budget: 10000 ms"))
        assertTrue(preview.contains("1. https / h1 / plain"))
        assertTrue(preview.contains("2. https / h2 / plain"))
        val suite = DptsScript.compile("dpts 1\nhost example.com\nsuite local_acceptance")
        assertTrue(DptsWorkspace.preview(suite).contains("Suite: local_acceptance"))
    }
}
