package com.dpsmpx.dppass.app

import com.dpsmpx.dppass.engine.xray.DptsScript
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Test

class DptsBuilderTest {
    @Test fun allModesProduceOrdinaryExecutableScripts() {
        for (mode in DptsBuilder.Mode.entries) {
            val draft = DptsBuilder.create("Example", "example.org", mode, setOf("plain"),
                2, 1, 1000, false)
            assertEquals(draft.plan, DptsScript.compile(draft.source))
            assertEquals(if (mode.name.endsWith("BOTH")) 4 else 2, draft.plan.probes.size)
        }
    }

    @Test fun methodsUseCatalogOrderAndBudget() {
        val draft = DptsBuilder.create("Example", "example.org", DptsBuilder.Mode.HTTPS_BOTH,
            linkedSetOf("split", "plain"), 2, 3, 5000, true)
        assertEquals(24, draft.plan.probes.size)
        assertEquals(120000L, draft.plan.budgetMs)
        assertEquals("plain", draft.plan.probes.first().method)
        assertEquals(true, draft.plan.observeLearning)
    }

    @Test fun invalidInputsCannotInjectStatementsOrExceedBudget() {
        val mode = DptsBuilder.Mode.HTTPS_BOTH
        assertThrows(IllegalArgumentException::class.java) {
            DptsBuilder.create("Example", "example.org\nlearn off", mode, setOf("plain"), 1, 1, 1000, false)
        }
        assertThrows(IllegalArgumentException::class.java) {
            DptsBuilder.create("bad\nname", "example.org", mode, setOf("plain"), 1, 1, 1000, false)
        }
        assertThrows(IllegalArgumentException::class.java) {
            DptsBuilder.create("Example", "example.org", mode, mode.methods().toSet(), 8, 3, 12000, false)
        }
        assertThrows(IllegalArgumentException::class.java) {
            DptsBuilder.create("Example", "example.org", DptsBuilder.Mode.QUIC, setOf("split"), 1, 1, 1000, false)
        }
    }
}
