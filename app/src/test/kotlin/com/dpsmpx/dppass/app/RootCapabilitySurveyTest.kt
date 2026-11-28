package com.dpsmpx.dppass.app

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class RootCapabilitySurveyTest {
    private val valid = "root_caps_v1\ncap=0000000000003000\nv4nat=1\nv4mangle=1\nv6nat=0\nv6mangle=1\n"
    private fun parse(text: String, exit: Int = 0) =
        RootCapabilitySurvey.parse(RootCommandRunner.CompleteResult(exit, text))

    @Test fun parsesCapabilitiesAndTablesIndependently() {
        assertEquals(RootCapabilitySurvey.Report(true, true, true, true, false, true), parse(valid))
        assertEquals(RootCapabilitySurvey.Report(false, true, true, true, false, true),
            parse(valid.replace("3000", "2000")))
        assertEquals(RootCapabilitySurvey.Report(true, false, true, true, false, true),
            parse(valid.replace("3000", "1000")))
        assertEquals(RootCapabilitySurvey.Report(false, false, true, true, false, true),
            parse(valid.replace("3000", "0000")))
    }

    @Test fun incompleteOrForeignOutputNeverConfirmsCapabilities() {
        for (bad in listOf("", valid.trimEnd(), valid.replace("3000", "x000"),
            valid.replace("v6nat=0", "v6nat=2"), valid.replace("v6nat=0", "v4nat=0"),
            valid + "extra\n", valid.replace("root_caps_v1", "root_caps_v2"))) {
            assertNull(parse(bad))
        }
        assertNull(parse(valid, 1))
    }

    @Test fun fixedCommandIsReadOnlyAndFailsClosed() {
        val script = RootCapabilitySurvey.script()
        for (expected in listOf("id -u", "CapEff:", "iptables -t nat -S OUTPUT",
            "iptables -t mangle -S OUTPUT", "ip6tables -t nat -S OUTPUT", "ip6tables -t mangle -S OUTPUT")) {
            assertTrue(script.contains(expected), expected)
        }
        for (forbidden in listOf(" -I ", " -A ", " -D ", " -F ", " -N ", "kill ", "mkdir ", "rm ")) {
            assertFalse(script.contains(forbidden), forbidden)
        }
        assertNull(RootCapabilitySurvey.run { _, _ -> error("su unavailable") })
        assertEquals(parse(valid), RootCapabilitySurvey.run { args, timeout ->
            assertEquals(listOf("su", "-c", script), args)
            assertEquals(15_000L, timeout)
            RootCommandRunner.CompleteResult(0, valid)
        })
    }
}
