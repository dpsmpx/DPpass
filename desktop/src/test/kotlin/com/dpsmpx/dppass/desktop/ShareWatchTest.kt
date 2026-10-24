package com.dpsmpx.dppass.desktop

import com.dpsmpx.dppass.core.IpAddress
import com.dpsmpx.dppass.diagnostics.Logger
import com.dpsmpx.dppass.diagnostics.MemoryLogSink
import com.dpsmpx.dppass.engine.ShareSpec
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/** Раздача под туннелем (D-84): смена набора адресов точки доступа — переподключение, одно. */
class ShareWatchTest {
    private val a = ShareSpec.Endpoint(IpAddress.parse("10.42.0.1")!!, 24)
    private val b = ShareSpec.Endpoint(IpAddress.parse("10.42.1.1")!!, 24)

    @Test
    fun newSetIsTakenOnlyWhenItHoldsForTwoPolls() {
        assertFalse(ShareWatch.shouldReconnect(listOf(a), listOf(a), null), "тот же набор")
        assertFalse(ShareWatch.shouldReconnect(emptyList(), listOf(a), null), "адрес появился — ждём второй опрос")
        assertTrue(ShareWatch.shouldReconnect(emptyList(), listOf(a), listOf(a)))
        assertFalse(ShareWatch.shouldReconnect(listOf(a), emptyList(), listOf(a)), "пропал на один опрос")
        assertTrue(ShareWatch.shouldReconnect(listOf(a), emptyList(), emptyList()), "точку доступа выключили")
        assertTrue(ShareWatch.shouldReconnect(listOf(a), listOf(b, a), listOf(a, b)), "порядок не важен")
    }

    @Test
    fun runReturnsOnceTheHotspotIsUpAndLogsCountsOnly() = runBlocking {
        val sink = MemoryLogSink()
        val polls = ArrayDeque(listOf(emptyList(), listOf(a), listOf(a)))
        var slept = 0L
        ShareWatch(Logger("test", sink, { 0L }), emptyList()) { polls.removeFirst() }.run { slept += it }
        assertTrue(polls.isEmpty(), "три опроса: пусто, адрес, тот же адрес")
        assertEquals(3 * ShareWatch.POLL_MILLIS, slept)
        val e = sink.snapshot().single { it.event == "share_interfaces_changed" }
        assertEquals("0", e.fields["was"])
        assertEquals("1", e.fields["now"])
        assertTrue(sink.snapshot().none { e2 -> e2.fields.values.any { "10.42" in it } }, "адресов в журнале нет")
    }
}
