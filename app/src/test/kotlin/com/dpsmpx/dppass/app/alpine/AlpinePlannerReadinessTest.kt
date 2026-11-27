package com.dpsmpx.dppass.app.alpine

import java.io.ByteArrayInputStream
import java.io.InputStream
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class AlpinePlannerReadinessTest {
    private val response = "{\"plan\":{\"strategy\":\"dppass:exp-split-1\",\"network\":\"tcp\",\"applied\":true,\"cut\":1}}\n"

    @Test fun fixedRequestAndCanonicalReply() {
        assertEquals("{\"tag\":\"dppass:exp-split-1\",\"network\":\"tcp\",\"first\":\"FgMBAAQBAAAA\"}\n",
            AlpinePlannerReadiness.request().decodeToString())
        assertTrue(AlpinePlannerReadiness.matches(response.byteInputStream()))
        val request = AlpinePlannerReadiness.request()
        request[0] = 0
        assertEquals('{'.code, AlpinePlannerReadiness.request()[0].toInt())
    }

    @Test fun rejectsFalseReadinessAndTruncatedFrames() {
        for (bad in listOf(
            response.replace("\"applied\":true", "\"applied\":false"),
            response.replace("\"cut\":1", "\"cut\":2"),
            response.replace("\"network\":\"tcp\"", "\"network\":\"udp\""),
            response.replace("split-1", "split-2"),
            response.replace("}}", "},\"error\":\"failure\"}"),
            response.replace("\"cut\":1", "\"cut\":1,\"cut\":1"),
            response.dropLast(1), response.take(20), "",
            "junk" + response, response.replace("\n", "\r\n"),
        )) assertFalse(AlpinePlannerReadiness.matches(bad.byteInputStream()), bad)
    }

    @Test fun boundedReaderNeverConsumesArbitraryLength() {
        var reads = 0
        val endless = object : InputStream() {
            override fun read(): Int { reads++; return '{'.code }
        }
        assertFalse(AlpinePlannerReadiness.matches(endless))
        assertEquals(2, reads)
        val frame = ByteArrayInputStream((response + "next frame").encodeToByteArray())
        assertTrue(AlpinePlannerReadiness.matches(frame))
        assertEquals('n'.code, frame.read())
    }

    @Test fun pathBoundUsesUtf8BytesAndAbsolutePath() {
        for (valid in listOf("/", "/" + "a".repeat(98), "/" + "é".repeat(49))) {
            assertTrue(AlpinePlannerReadiness.validSocketPath(valid))
        }
        for (bad in listOf("", "relative", "/a\u0000b", "/" + "a".repeat(99), "/" + "é".repeat(50))) {
            assertFalse(AlpinePlannerReadiness.validSocketPath(bad))
        }
    }
}
