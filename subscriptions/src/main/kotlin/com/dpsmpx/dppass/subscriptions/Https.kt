package com.dpsmpx.dppass.subscriptions

import com.dpsmpx.dppass.core.Clock
import com.dpsmpx.dppass.diagnostics.DiagCode
import com.dpsmpx.dppass.diagnostics.Diagnostic
import com.dpsmpx.dppass.diagnostics.Outcome
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.io.InputStream
import java.net.HttpURLConnection
import java.net.MalformedURLException
import java.net.SocketTimeoutException
import java.net.URL
import java.util.concurrent.ScheduledThreadPoolExecutor
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference

/**
 * Загрузка подписки по HTTPS (D-36; работа 2 этапа 3, сделана раньше по
 * решению автора).
 *
 * - Только `https://`, системные CA (своих `TrustManager` нет, T5);
 *   переадресация — вручную и тоже только на `https://`, не больше
 *   [MAX_REDIRECTS] раз.
 * - Заголовки — ровно [SubscriptionRequest]: `User-Agent` DPpass и
 *   `x-hwid`, только если пользователь его включил (D-12, D-33).
 * - Тайм-аут и предел размера — [FetchPolicy]; предел действует во время
 *   чтения, а не после: огромный ответ не попадает в память.
 * - Ответ не 2xx — отказ с кодом HTTP; адреса в сообщении нет (в нём
 *   токен). Исключение — отказ по лимиту устройств (`x-hwid-*`): такой ответ
 *   отдаётся конвейеру, и тот называет его своим кодом (D-33).
 *
 * Блокирует поток: вызывать в фоне. Загрузка идёт из процесса
 * приложения, то есть мимо туннеля (собственный пакет в туннель не входит, D-17).
 */
class HttpsSubscriptionFetcher(
    private val clock: Clock,
    private val deadlineClock: Clock = Clock.MONOTONIC,
    private val open: (URL) -> HttpURLConnection = { it.openConnection() as HttpURLConnection },
) : SubscriptionFetcher {
    override suspend fun fetch(request: SubscriptionRequest, policy: FetchPolicy): Outcome<FetchedPayload> {
        val source = request.source as? SubscriptionSource.Url
            ?: return Outcome.failure(DiagCode.SUBSCRIPTION_FETCH_FAILED, "у своих серверов адреса нет — загружать нечего")
        var url = try {
            URL(source.url.reveal())
        } catch (e: MalformedURLException) {
            return Outcome.failure(DiagCode.SUBSCRIPTION_FETCH_FAILED, "адрес подписки — не адрес")
        }
        if (url.protocol != "https") return Outcome.failure(DiagCode.SUBSCRIPTION_FETCH_FAILED, "подписка загружается только по https://")
        val timeout = policy.timeoutMillis.coerceIn(1_000, 120_000).toInt()
        val initial = url
        val budget = Deadline(timeout.toLong())
        try {
            repeat(MAX_REDIRECTS + 1) {
                val c = try {
                    open(url)
                } catch (e: IOException) {
                    return unreachable(e)
                }
                try {
                    budget.watch(c)
                    c.instanceFollowRedirects = false
                    c.useCaches = false
                    c.connectTimeout = timeout
                    c.readTimeout = timeout
                    c.requestMethod = "GET"
                    c.setRequestProperty("User-Agent", request.userAgent)
                    c.setRequestProperty("Accept", "*/*")
                    if (sameOrigin(initial, url)) {
                        request.deviceId?.let { c.setRequestProperty(SubscriptionRequest.DEVICE_ID_HEADER, it.reveal()) }
                    }
                    val code = c.responseCode
                    budget.check()
                    if (code in 300..399) {
                        val location = c.getHeaderField("Location")
                            ?: return Outcome.failure(DiagCode.SUBSCRIPTION_FETCH_FAILED, "переадресация HTTP $code без адреса")
                        url = try {
                            URL(url, location)
                        } catch (e: MalformedURLException) {
                            return Outcome.failure(DiagCode.SUBSCRIPTION_FETCH_FAILED, "переадресация HTTP $code на неверный адрес")
                        }
                        if (url.protocol != "https") {
                            return Outcome.failure(DiagCode.SUBSCRIPTION_FETCH_FAILED, "переадресация не на https:// не выполняется")
                        }
                        return@repeat
                    }
                    val headers = c.headerFields.orEmpty()
                        .filterKeys { it != null }
                        .map { (k, v) -> k.lowercase() to v.joinToString(", ") }
                        .toMap()
                    val refusal = headers["x-hwid-not-supported"] == "true" || headers["x-hwid-max-devices-reached"] == "true"
                    if (code !in 200..299 && !refusal) {
                        return Outcome.failure(DiagCode.SUBSCRIPTION_FETCH_FAILED, "сервер подписки ответил HTTP $code")
                    }
                    // У отказа с ошибочным кодом тела может не быть вовсе.
                    val stream: InputStream? = if (code in 200..299) c.inputStream else c.errorStream
                    val bytes = if (stream == null) {
                        ByteArray(0)
                    } else {
                        stream.use { readLimited(it, policy.maxBytes, budget::check) }
                            ?: return Outcome.failure(DiagCode.SUBSCRIPTION_TOO_LARGE, "ответ больше ${policy.maxBytes} байт — чтение прервано")
                    }
                    return Outcome.Success(FetchedPayload(bytes, headers, clock.nowMillis()))
                } catch (e: IOException) {
                    return unreachable(e)
                } finally {
                    c.disconnect()
                }
            }
            return Outcome.failure(DiagCode.SUBSCRIPTION_FETCH_FAILED, "больше $MAX_REDIRECTS переадресаций")
        } finally { budget.close() }
    }

    private fun sameOrigin(first: URL, next: URL): Boolean =
        first.protocol.equals(next.protocol, ignoreCase = true) && first.host.equals(next.host, ignoreCase = true) &&
            (if (first.port < 0) first.defaultPort else first.port) == (if (next.port < 0) next.defaultPort else next.port)

    /** Один срок на заголовки, переадресации и тело; таймер закрывает зависший сокет. */
    private inner class Deadline(private val millis: Long) : AutoCloseable {
        private val start = deadlineClock.nowMillis()
        private val expired = AtomicBoolean()
        private val active = AtomicReference<HttpURLConnection?>()
        private val timer = deadlines.schedule({
            expired.set(true)
            active.get()?.disconnect()
        }, millis, TimeUnit.MILLISECONDS)

        fun watch(connection: HttpURLConnection) {
            active.set(connection)
            check()
        }

        fun check() {
            if (expired.get() || deadlineClock.nowMillis() - start >= millis) {
                active.get()?.disconnect()
                throw SocketTimeoutException("истёк общий срок загрузки подписки")
            }
        }

        override fun close() { timer.cancel(false); active.set(null) }
    }

    private fun unreachable(e: IOException): Outcome.Failure =
        Outcome.failure(Diagnostic.fromThrowable(DiagCode.ENDPOINT_UNREACHABLE, "сервер подписки недоступен", e))

    companion object {
        const val MAX_REDIRECTS: Int = 3
        private val deadlines = ScheduledThreadPoolExecutor(1) { work -> Thread(work, "dppass-subscription-deadline").apply { isDaemon = true } }
            .apply { removeOnCancelPolicy = true }

        /** Не больше [max] байт; больше — null, и лишнее не читается дальше одного байта сверх предела. */
        fun readLimited(input: InputStream, max: Int, checkDeadline: () -> Unit = {}): ByteArray? {
            val out = ByteArrayOutputStream()
            val buf = ByteArray(16 * 1024)
            var total = 0L
            while (true) {
                checkDeadline()
                val want = minOf(buf.size.toLong(), max.toLong() + 1 - total).toInt()
                if (want <= 0) return null
                val n = input.read(buf, 0, want)
                checkDeadline()
                if (n < 0) return out.toByteArray()
                total += n
                if (total > max) return null
                out.write(buf, 0, n)
            }
        }
    }
}
