package com.dpsmpx.dppass.app

import com.dpsmpx.dppass.engine.TrafficStats
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull

class LocalPathSampleTest {
    private fun sample(pu: Long, pd: Long, au: Long, ad: Long) =
        LocalPathSample(TrafficStats(pu, pd), TrafficStats(au, ad))

    @Test fun subtractsStartupBaselineAndSeparatesOtherTraffic() {
        val base = sample(100, 200, 300, 400)
        assertEquals(LocalPathDelta(10, 20, 40, 60),
            sample(110, 220, 350, 480).deltaFrom(base))
    }

    @Test fun emptyIntervalIsNotAFailure() {
        val base = sample(1, 2, 3, 4)
        assertEquals(LocalPathDelta(0, 0, 0, 0), base.deltaFrom(base))
    }

    @Test fun rejectsResetOrInconsistentSnapshot() {
        assertNull(sample(1, 2, 3, 4).deltaFrom(sample(2, 3, 4, 5)))
        assertNull(sample(10, 20, 9, 19).deltaFrom(sample(0, 0, 0, 0)))
    }
}
