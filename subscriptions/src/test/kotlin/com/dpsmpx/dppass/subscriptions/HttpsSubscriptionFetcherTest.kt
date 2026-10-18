package com.dpsmpx.dppass.subscriptions

import com.dpsmpx.dppass.core.ManualClock
import com.dpsmpx.dppass.core.SubscriptionId
import com.dpsmpx.dppass.diagnostics.DiagCode
import com.dpsmpx.dppass.diagnostics.Outcome
import com.dpsmpx.dppass.diagnostics.Secret
import kotlinx.coroutines.runBlocking
import java.io.ByteArrayInputStream
import java.io.InputStream
import java.net.HttpURLConnection
import java.net.SocketTimeoutException
import java.net.URL
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertTrue

/** Соединение без сети: ответ задан тестом, заголовки запроса записываются. */
private class FakeConnection(
    url: URL,
    private val code: Int,
    private val headers: Map<String, String> = emptyMap(),
    private val body: () -> InputStream = { ByteArrayInputStream(ByteArray(0)) },
) : HttpURLConnection(url) {
    val sent = LinkedHashMap<String, String>()

    override fun setRequestProperty(key: String, value: String) {
        sent[key] = value
    }

    override fun getResponseCode(): Int = code
    override fun getHeaderFields(): Map<String?, List<String>> = headers.mapValues { listOf(it.value) } + mapOf(null to listOf("HTTP/1.1 $code"))
    override fun getHeaderField(name: String): String? = headers.entries.firstOrNull { it.key.equals(name, ignoreCase = true) }?.value
    override fun getInputStream(): InputStream = body()
    override fun getErrorStream(): InputStream = body()
    override fun connect() = Unit
    override fun disconnect() = Unit
    override fun usingProxy(): Boolean = false
}

class HttpsSubscriptionFetcherTest {
    private val clock = ManualClock(0)
    private val policy = FetchPolicy()

    private fun request(url: String, deviceId: Secret? = null) =
        SubscriptionRequest(SubscriptionSource.Url(Secret(url)), "DPpass/test", deviceId)

    private fun fetch(req: SubscriptionRequest, vararg answers: FakeConnection, p: FetchPolicy = policy): Pair<Outcome<FetchedPayload>, List<URL>> {
        val opened = mutableListOf<URL>()
        val queue = ArrayDeque(answers.toList())
        val f = HttpsSubscriptionFetcher(clock) { url -> opened += url; queue.removeFirst() }
        return runBlocking { f.fetch(req, p) } to opened
    }

    @Test
    fun onlyHttpsIsFetched() {
        val (r, opened) = fetch(request("http://sub.example.com/token-1"))
        assertIs<Outcome.Failure>(r)
        assertTrue(opened.isEmpty(), "по http:// соединение не открывается")
    }

    @Test
    fun sendsExactlyTheRequestHeaders() {
        val url = URL("https://sub.example.com/token-1")
        val plain = FakeConnection(url, 200)
        fetch(request(url.toString()), plain)
        assertEquals(setOf("User-Agent", "Accept"), plain.sent.keys)
        assertEquals("DPpass/test", plain.sent["User-Agent"])

        val id = DeviceId.generate()
        val withId = FakeConnection(url, 200)
        fetch(request(url.toString(), id), withId)
        assertEquals(setOf("User-Agent", "Accept", "x-hwid"), withId.sent.keys)
        assertEquals(id.reveal(), withId.sent["x-hwid"])
    }

    @Test
    fun timeoutIsSetForConnectAndReadWithinBounds() {
        assertEquals(20_000L, FetchPolicy().timeoutMillis, "как в PERFORMANCE_BUDGET §2")
        val url = URL("https://sub.example.com/token-1")
        for ((asked, applied) in listOf(20_000L to 20_000, 10L to 1_000, 600_000L to 120_000)) {
            val c = FakeConnection(url, 200)
            fetch(request(url.toString()), c, p = FetchPolicy(timeoutMillis = asked))
            assertEquals(applied to applied, c.connectTimeout to c.readTimeout, "срок $asked мс")
        }
        // Срок вышел посреди тела: отказ «сервер недоступен», а не обрезанная подписка.
        val stalled = FakeConnection(url, 200, body = {
            object : InputStream() {
                override fun read(): Int = throw SocketTimeoutException("Read timed out")
            }
        })
        val (r, _) = fetch(request(url.toString()), stalled)
        assertEquals(DiagCode.ENDPOINT_UNREACHABLE, assertIs<Outcome.Failure>(r).errors.single().code)
    }

    @Test
    fun sizeLimitStopsReadingEarly() {
        var read = 0L
        val endless = object : InputStream() {
            override fun read(): Int = 'A'.code.also { read++ }
            override fun read(b: ByteArray, off: Int, len: Int): Int {
                b.fill('A'.code.toByte(), off, off + len)
                read += len
                return len
            }
        }
        val url = URL("https://sub.example.com/token-1")
        val (r, _) = fetch(request(url.toString()), FakeConnection(url, 200) { endless }, p = FetchPolicy(maxBytes = 1000))
        assertEquals(DiagCode.SUBSCRIPTION_TOO_LARGE, r.errors.single().code)
        assertTrue(read <= 1001, "прочитано $read байт при пределе 1000")
    }

    @Test
    fun redirectsFollowOnlyHttps() {
        val a = URL("https://sub.example.com/token-1")
        val b = URL("https://sub2.example.com/token-1")
        val (ok, opened) = fetch(
            request(a.toString()),
            FakeConnection(a, 302, mapOf("Location" to b.toString())),
            FakeConnection(b, 200, mapOf("Profile-Title" to "T")) { ByteArrayInputStream("x".toByteArray()) },
        )
        assertEquals(listOf(a, b), opened)
        assertEquals("T", ok.valueOrNull()!!.headers["profile-title"], "имена заголовков — в нижнем регистре")

        val (bad, opened2) = fetch(request(a.toString()), FakeConnection(a, 301, mapOf("Location" to "http://sub.example.com/token-1")))
        assertIs<Outcome.Failure>(bad)
        assertEquals(listOf(a), opened2)
    }

    @Test
    fun httpErrorNamesStatusNotAddress() {
        val url = URL("https://sub.example.com/token-1")
        val (r, _) = fetch(request(url.toString()), FakeConnection(url, 500))
        val message = r.errors.single().message
        assertTrue("500" in message, message)
        assertFalse("token-1" in message, message)
    }

    @Test
    fun deviceRefusalOnErrorStatusReachesThePipeline() = runBlocking {
        // Remnawave может ответить и 404 с признаками лимита устройств: это отказ D-33, а не «ошибка HTTP».
        val url = URL("https://sub.example.com/token-1")
        val conn = FakeConnection(url, 404, mapOf("x-hwid-active" to "true", "x-hwid-not-supported" to "true"))
        val f = HttpsSubscriptionFetcher(clock) { conn }
        val sub = Subscription(SubscriptionId("s1"), "S", SubscriptionSource.Url(Secret(url.toString())))
        val r = SubscriptionUpdater(f, clock, "test").update(sub) { ps, _ -> FilterResult(ps, emptyList()) }
        assertEquals(DiagCode.SUBSCRIPTION_DEVICE_ID_REQUIRED, (r as UpdateResult.Failed).subscription.lastFailed!!.reason.code)
    }
}
