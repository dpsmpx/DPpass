package com.dpsmpx.dppass.app.alpine

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Test

class AlpineCommandHistoryTest {
    @Test fun navigationReturnsToUnsentDraft() {
        val history = AlpineCommandHistory()
        history.record("pwd")
        history.record("apk info")
        assertEquals("apk info", history.previous("unfinished"))
        assertEquals("pwd", history.previous("apk info"))
        assertEquals("pwd", history.previous("pwd"))
        assertEquals("apk info", history.next())
        assertEquals("unfinished", history.next())
        assertNull(history.next())
    }

    @Test fun sessionHistoryIsBoundedAndCleared() {
        val history = AlpineCommandHistory(2)
        history.record("first")
        history.record("second")
        history.record("second")
        history.record("third")
        history.record(" ")
        history.record("x".repeat(4097))
        assertEquals(listOf("third", "second"), history.recent())
        history.clear()
        assertEquals(emptyList<String>(), history.recent())
        assertNull(history.previous("draft"))
    }
}
