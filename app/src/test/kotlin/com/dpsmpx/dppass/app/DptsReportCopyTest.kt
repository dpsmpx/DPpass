package com.dpsmpx.dppass.app

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class DptsReportCopyTest {
    @Test fun successAndUnavailableClipboardAreDistinct() {
        var writes = 0
        assertTrue(DptsReportCopy.attempt { writes++; true })
        assertFalse(DptsReportCopy.attempt { writes++; false })
        assertEquals(2, writes)
    }

    @Test fun platformAccessFailuresDoNotDiscardCompletedReport() {
        assertFalse(DptsReportCopy.attempt { throw SecurityException() })
        assertFalse(DptsReportCopy.attempt { throw IllegalStateException() })
        assertThrows(AssertionError::class.java) {
            DptsReportCopy.attempt { throw AssertionError("unexpected failure") }
        }
    }
}
