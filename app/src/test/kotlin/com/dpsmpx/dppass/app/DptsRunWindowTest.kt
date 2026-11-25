package com.dpsmpx.dppass.app

import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class DptsRunWindowTest {
    @Test fun preparationConsumesTheSameOverallDeadline() {
        val window = DptsRunWindow(100L, 12000)
        assertTrue(window.canStart(12000L, 12000))
        assertTrue(window.canStart(239999L, 12000))
        assertFalse(window.canStart(240100L, 12000))
        assertTrue(window.canFinish(252099L))
        assertFalse(window.canFinish(252100L))
        assertFalse(window.canFinish(99L))
        assertFalse(window.canStart(100L, 999))
        assertFalse(window.canStart(100L, 12001))
    }

    @Test fun deadlineCannotExceedNativePreparationLifetime() {
        val window = DptsRunWindow(0L, 120000)
        assertTrue(window.canFinish(299999L))
        assertFalse(window.canFinish(300000L))
        assertFalse(window.canStart(299000L, 1000))
        assertFalse(DptsRunWindow(-1L, 12000).canFinish(0L))
    }

    @Test fun ContractFailuresAreNotOrdinaryNetworkObservations() {
        for (outcome in listOf("engine_off", "dns_not_prepared", "invalid_target",
            "invalid_strategy", "invalid_index", "invalid_timeout", "unsupported",
            "contract_error")) {
            assertTrue(DptsRunWindow.invalidExecution(outcome))
        }
        for (outcome in listOf("ok", "timeout_tls_no_reply", "dial_failed",
            "http_status", "quic_timeout_no_reply")) {
            assertFalse(DptsRunWindow.invalidExecution(outcome))
        }
    }
}
