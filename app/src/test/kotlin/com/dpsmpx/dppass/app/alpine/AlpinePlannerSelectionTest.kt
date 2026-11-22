package com.dpsmpx.dppass.app.alpine

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test

class AlpinePlannerSelectionTest {
    @Test fun standardBuildUsesOneSharedInProcessPlanner() {
        assertEquals(
            AlpinePlannerSelection.IN_PROCESS,
            AlpinePlannerSelection.choose(bundled = false, supported = false),
        )
    }

    @Test fun bundledRuntimeSelectsProotDaemon() {
        assertEquals(
            AlpinePlannerSelection.ALPINE,
            AlpinePlannerSelection.choose(bundled = true, supported = true),
        )
    }

    @Test fun missingProotInBundledApkCannotSilentlyFallBack() {
        assertEquals(
            AlpinePlannerSelection.UNAVAILABLE,
            AlpinePlannerSelection.choose(bundled = true, supported = false),
        )
    }

    @Test fun unsupportedFlagCannotEnableAlpineInStandardBuild() {
        assertEquals(
            AlpinePlannerSelection.IN_PROCESS,
            AlpinePlannerSelection.choose(bundled = false, supported = true),
        )
    }
}
