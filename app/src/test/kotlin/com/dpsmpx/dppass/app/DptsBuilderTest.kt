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

    @Test fun appendBuildsMixedMatrixAndRetainsOriginalMetadata() {
        val original = "# comment\r\ndpts 1\r\nname Example\r\nhost example.org\r\nlearn observe\r\nhttps protocols=h2 methods=plain ips=1 attempts=1 timeout_ms=1000"
        val tls = DptsBuilder.append(original, DptsBuilder.Mode.TLS_BOTH,
            setOf("plain"), 1, 1, 2000)
        val quic = DptsBuilder.append(tls.source, DptsBuilder.Mode.QUIC,
            setOf("plain"), 1, 1, 3000)
        assertEquals(true, quic.source.startsWith(original + "\n"))
        assertEquals("Example", quic.plan.title)
        assertEquals("example.org", quic.plan.host)
        assertEquals(true, quic.plan.observeLearning)
        assertEquals(listOf("h2", "tls12", "tls13", "quic"), quic.plan.probes.map { it.protocol })
        assertEquals(8000L, quic.plan.budgetMs)
        assertEquals(quic.plan, DptsScript.compile(quic.source))
    }

    @Test fun appendRejectsDuplicateProbesFixedSuitesAndCombinedBudgetOverflow() {
        val existing = DptsBuilder.create("Example", "example.org", DptsBuilder.Mode.HTTPS_H1,
            setOf("plain"), 8, 2, 12000, false)
        assertThrows(IllegalArgumentException::class.java) {
            DptsBuilder.append(existing.source, DptsBuilder.Mode.HTTPS_H1, setOf("plain"), 1, 1, 1000)
        }
        assertThrows(IllegalArgumentException::class.java) {
            DptsBuilder.append(existing.source, DptsBuilder.Mode.QUIC, setOf("plain"), 8, 1, 12000)
        }
        assertThrows(IllegalArgumentException::class.java) {
            DptsBuilder.append("dpts 1\nhost example.com\nsuite local_acceptance",
                DptsBuilder.Mode.QUIC, setOf("plain"), 1, 1, 1000)
        }
        assertThrows(IllegalArgumentException::class.java) {
            DptsBuilder.append("dpts 1", DptsBuilder.Mode.QUIC, setOf("plain"), 1, 1, 1000)
        }
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
