package com.dpsmpx.dppass.engine.xray

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class Zapret2QuicMetricsTest {
    @Test fun validV4HasPublicHeaderMetricsButNoVerifiedTLSClaim() {
        val r=Zapret2GoogleProbe.fromWire(
            "v4\tquic_timeout_after_reply\t0\t0\t6001\t0\t0\t8020f565\t8\t0\tquic\tquic_peer_initial_header\t-\t3\t1\t320\t1200".encodeToByteArray())
        assertEquals("quic_timeout_after_reply",r.outcome)
        assertEquals(3,r.quicInitialTx)
        assertEquals(1,r.quicPeerRx)
        assertEquals(320,r.quicFirstReplyMillis)
        assertEquals(1200,r.quicMaxInitialBytes)
        assertEquals("-",r.alpn)
    }
    @Test fun malformedCountersOrTCPV4CannotBypassStrictContract() {
        val valid="v4\tquic_timeout_no_reply\t0\t0\t6000\t0\t0\t8020f565\t8\t0\tquic\tquic_initial_sent\t-\t2\t0\t0\t1200"
        for (bad in listOf(
                valid.replace("\t2\t0\t0\t1200","\t-1\t0\t0\t1200"),
                valid.replace("\t2\t0\t0\t1200","\t2\t0\t5\t1200"),
                valid.replace("\t2\t0\t0\t1200","\t0\t0\t0\t1200"),
                valid.replace("\tquic\tquic_initial_sent","\th1\ttls_verified"),
                valid.replace("\t2\t0\t0\t1200","\t2\t256\t0\t1200"),
                valid.replace("\t2\t0\t0\t1200","\t2\t0\t0\t99999"),
                valid.dropLast(4),
            )) {
            assertEquals("contract_error",
                Zapret2GoogleProbe.fromWire(bad.encodeToByteArray()).outcome,bad)
        }
        assertTrue(Zapret2GoogleProbe.fromWire(
            valid.encodeToByteArray()).outcome=="quic_timeout_no_reply")
    }
}
