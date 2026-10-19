package com.dpsmpx.dppass.app.ui

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/** Протяжка вниз (D-70): когда замер начинается, а когда нет. */
class PullGestureTest {
    private fun gesture() = PullGesture(thresholdPx = 72f, maxPx = 120f)

    @Test
    fun pullPastTheThresholdStartsOnRelease() {
        val g = gesture()
        g.drag(100f)
        assertEquals(50f, g.offset, "значок идёт вдвое медленнее пальца")
        assertFalse(g.armed)
        g.drag(150f)
        assertTrue(g.armed)
        assertEquals(1f, g.progress)
        assertTrue(g.release(), "отпустил за порогом — замер")
        assertEquals(0f, g.offset, "после отпускания значок уходит")
        assertFalse(g.armed)
    }

    @Test
    fun shortPullOrPullBackDoesNotStart() {
        val g = gesture()
        g.drag(100f)
        assertEquals(50f / 72f, g.progress)
        assertFalse(g.release(), "не дотянул — без замера")

        g.drag(200f)
        assertTrue(g.armed)
        g.drag(40f)
        assertFalse(g.armed, "вернул палец вверх — передумал")
        assertFalse(g.release())

        g.drag(-30f)
        assertEquals(0f, g.offset, "вверх — не протяжка")
    }

    @Test
    fun indicatorStopsAtItsLimitAndCancelStartsNothing() {
        val g = gesture()
        g.drag(10_000f)
        assertEquals(120f, g.offset)
        g.cancel()
        assertEquals(0f, g.offset)
        assertFalse(g.release(), "касание отменено — замера нет")
    }

    @Test
    fun thresholdMustFitUnderTheLimit() {
        assertFailsWith<IllegalArgumentException> { PullGesture(thresholdPx = 0f, maxPx = 10f) }
        assertFailsWith<IllegalArgumentException> { PullGesture(thresholdPx = 80f, maxPx = 40f) }
    }
}
