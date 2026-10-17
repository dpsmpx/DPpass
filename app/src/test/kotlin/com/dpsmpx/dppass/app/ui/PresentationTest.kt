package com.dpsmpx.dppass.app.ui

import com.dpsmpx.dppass.config.ProtocolSpec
import com.dpsmpx.dppass.config.SecuritySpec
import com.dpsmpx.dppass.config.ServerProfile
import com.dpsmpx.dppass.config.ShadowsocksMethod
import com.dpsmpx.dppass.config.TlsFingerprint
import com.dpsmpx.dppass.config.TransportSpec
import com.dpsmpx.dppass.config.XHttpMode
import com.dpsmpx.dppass.connection.CandidateHealth
import com.dpsmpx.dppass.connection.HealthState
import com.dpsmpx.dppass.core.Endpoint
import com.dpsmpx.dppass.core.Host
import com.dpsmpx.dppass.core.ProfileId
import com.dpsmpx.dppass.core.SubscriptionId
import com.dpsmpx.dppass.diagnostics.DiagCode
import com.dpsmpx.dppass.diagnostics.Diagnostic
import com.dpsmpx.dppass.diagnostics.FailureKind
import com.dpsmpx.dppass.diagnostics.Secret
import com.dpsmpx.dppass.subscriptions.FailedRevision
import com.dpsmpx.dppass.subscriptions.Subscription
import com.dpsmpx.dppass.subscriptions.SubscriptionMetadata
import com.dpsmpx.dppass.subscriptions.SubscriptionRevision
import com.dpsmpx.dppass.subscriptions.SubscriptionSource
import com.dpsmpx.dppass.subscriptions.SubscriptionsState
import com.dpsmpx.dppass.subscriptions.TrafficInfo
import java.util.Locale
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** Логика экранов (D-34) — без Android. */
class PresentationTest {
    private val endpoint = Endpoint(Host.Domain("vpn.example.net"), 443)
    private val tls = SecuritySpec.Tls("vpn.example.net", emptyList(), TlsFingerprint.CHROME)

    private fun profile(id: String, protocol: ProtocolSpec, transport: TransportSpec, security: SecuritySpec) =
        ServerProfile(ProfileId(id), "Сервер $id", endpoint, protocol, transport, security)

    private val reality = profile(
        "a",
        ProtocolSpec.Vless(Secret("00000000-0000-4000-8000-000000000001")),
        TransportSpec.Tcp,
        SecuritySpec.Reality("www.example.com", "pk", Secret("ab"), TlsFingerprint.CHROME, null),
    )
    private val trojanWs = profile("b", ProtocolSpec.Trojan(Secret("p")), TransportSpec.WebSocket("/ws", null), tls)
    private val hy2 = profile("c", ProtocolSpec.Hysteria2(Secret("p")), TransportSpec.Native, tls)
    private val ss = profile("d", ProtocolSpec.Shadowsocks(ShadowsocksMethod.BLAKE3_AES_128_GCM, Secret("k")), TransportSpec.Native, SecuritySpec.None)
    private val xhttp = profile("e", ProtocolSpec.Vless(Secret("00000000-0000-4000-8000-000000000002")), TransportSpec.XHttp("/x", null, XHttpMode.AUTO), tls)

    @Test
    fun summaryNamesProtocolSecurityAndTransport() {
        assertEquals("VLESS · REALITY · TCP", ServerList.summary(reality))
        assertEquals("Trojan · TLS · WebSocket", ServerList.summary(trojanWs))
        assertEquals("VLESS · TLS · XHTTP", ServerList.summary(xhttp))
        // У Hysteria2 TLS — часть протокола, транспорт — QUIC.
        assertEquals("Hysteria2 · QUIC", ServerList.summary(hy2))
        assertEquals("Shadowsocks 2022", ServerList.summary(ss))
    }

    @Test
    fun rowsKeepConfigOrderAndShowHealth() {
        val now = 1_000_000L
        val health = mapOf(
            reality.id to CandidateHealth(HealthState.HEALTHY, lastSuccessMillis = now - 5),
            trojanWs.id to CandidateHealth(HealthState.FAILED, 1, DiagCode.TLS_HANDSHAKE_FAILED, backoffUntilMillis = now + 1_500),
            hy2.id to CandidateHealth(HealthState.FAILED, 3, DiagCode.ENDPOINT_UNREACHABLE, backoffUntilMillis = now - 1),
        )
        val rows = ServerList.rows(listOf(reality, trojanWs, hy2, ss), { health[it] ?: CandidateHealth() }, trojanWs.id, reality.id, now)
        assertEquals(listOf("a", "b", "c", "d"), rows.map { it.id.value })
        assertEquals(listOf(RowHealth.HEALTHY, RowHealth.PAUSED, RowHealth.FAILED, RowHealth.UNKNOWN), rows.map { it.health })
        assertEquals(2, rows[1].pauseSeconds, "остаток паузы — вверх до секунды")
        assertEquals(FailureKind.TLS_HANDSHAKE_FAILED, rows[1].lastFailure)
        assertEquals(listOf(false, true, false, false), rows.map { it.selected })
        assertEquals(listOf(true, false, false, false), rows.map { it.connected })
    }

    @Test
    fun selectionOfVanishedServerIsAutomatic() {
        // Подписка обновилась, выбранного сервера в ней больше нет — выбор «автоматически».
        assertNull(ServerList.effectiveSelection(listOf(reality), ProfileId("gone")))
        val rows = ServerList.rows(listOf(reality), { CandidateHealth() }, ProfileId("gone"), null, 0)
        assertFalse(rows.single().selected)
        assertEquals(reality.id, ServerList.effectiveSelection(listOf(reality, hy2), reality.id))
    }

    @Test
    fun configSourceFromActivationRecord() {
        assertEquals(ConfigSource.None, ConfigSource.of(null))
        assertEquals(ConfigSource.Own, ConfigSource.of("user-import"))
        assertEquals(ConfigSource.FromSubscription(SubscriptionId("s2")), ConfigSource.of("subscription:s2#7"))
    }

    @Test
    fun subscriptionRowShowsLastResultTrafficAndExpiry() {
        val ok = SubscriptionRevision(3, "c3", fetchedAtMillis = 5_000, profileCount = 4)
        val fail = FailedRevision(null, 6_000, Diagnostic.error(DiagCode.SUBSCRIPTION_DEVICE_ID_REQUIRED, "нужен идентификатор"))
        val s1 = Subscription(
            SubscriptionId("s1"),
            "provider.example.net",
            SubscriptionSource.Url(Secret("https://provider.example.net/sub/token")),
            metadata = SubscriptionMetadata(
                title = "Мой поставщик",
                traffic = TrafficInfo(uploadBytes = 1024, downloadBytes = 2048, totalBytes = 0, expireEpochSeconds = 7),
                announce = "Профилактика\u0007 в 03:00\n",
            ),
            lastSuccessful = ok,
            lastFailed = fail,
        )
        val s2 = Subscription(
            SubscriptionId("s2"), "второй", SubscriptionSource.Url(Secret("https://b.example.org/x")), lastSuccessful = ok,
            lastFailed = FailedRevision(null, 4_000, fail.reason),
        )
        val rows = SubscriptionList.rows(SubscriptionsState(listOf(s1, s2), SubscriptionId("s1")), ConfigSource.FromSubscription(SubscriptionId("s1")), 7_000)
        val r = rows[0]
        assertEquals("Мой поставщик", r.name, "название поставщика — вместо имени по адресу")
        assertTrue(r.active)
        assertEquals(4, r.profileCount)
        assertEquals(DiagCode.SUBSCRIPTION_DEVICE_ID_REQUIRED, r.failure?.code, "отказ позже удачной загрузки — показывается")
        assertEquals(3072L, r.usedBytes)
        assertNull(r.totalBytes, "0 у поставщика — без предела")
        assertTrue(r.expired)
        assertEquals("Профилактика в 03:00", r.announce)
        assertFalse(rows[1].active)
        assertNull(rows[1].failure, "отказ раньше удачной загрузки — уже не новость")
    }

    @Test
    fun subscriptionRowShowsUsersNameOverProviderTitle() {
        // D-53: имя, данное пользователем, поставщик не перебивает; окно переименования подставляет его же.
        val s = Subscription(
            SubscriptionId("s1"), "Мой VPN", SubscriptionSource.Url(Secret("https://provider.example.net/sub/token")),
            metadata = SubscriptionMetadata(title = "Мой поставщик"), nameByUser = true,
        )
        assertEquals("Мой VPN", SubscriptionList.rows(SubscriptionsState(listOf(s), null), ConfigSource.None, 0).single().name)
    }

    @Test
    fun subscriptionIsNotActiveWhenOwnConfigReplacedIt() {
        val s = Subscription(SubscriptionId("s1"), "a", SubscriptionSource.Url(Secret("https://a.example.net/s")))
        val rows = SubscriptionList.rows(SubscriptionsState(listOf(s), SubscriptionId("s1")), ConfigSource.Own, 0)
        assertFalse(rows.single().active)
    }

    @Test
    fun announceIsLimited() {
        val long = "а".repeat(ANNOUNCE_LIMIT + 50)
        assertEquals(ANNOUNCE_LIMIT, SubscriptionList.plain(long).length)
        assertTrue(SubscriptionList.plain(long).endsWith("…"))
    }

    @Test
    fun bytesInBinaryUnits() {
        val units = listOf("Б", "КБ", "МБ", "ГБ", "ТБ")
        val ru = Locale.forLanguageTag("ru")
        assertEquals("512 Б", Formats.bytes(512, units, ru))
        assertEquals("1,5 КБ", Formats.bytes(1536, units, ru))
        assertEquals("1.5 KB", Formats.bytes(1536, listOf("B", "KB", "MB", "GB", "TB"), Locale.ENGLISH))
        assertEquals("50 ГБ", Formats.bytes(50L shl 30, units, ru))
        assertEquals("2048 ТБ", Formats.bytes(2048L shl 40, units, ru))
        assertEquals("0 Б", Formats.bytes(-5, units, ru))
    }

    @Test
    fun avatarIsFlagOrFirstLetter() {
        assertEquals("🇩🇪", Avatar.of("🇩🇪 Германия · 1"))
        assertEquals("Германия · 1", Avatar.stripFlag("🇩🇪 Германия · 1"))
        assertEquals("N", Avatar.of("  nl-amsterdam"))
        assertEquals("•", Avatar.of("—"))
        // Один региональный символ — не флаг.
        assertEquals("X", Avatar.of("\uD83C\uDDE9 x"))
        assertEquals("plain", Avatar.stripFlag("plain"))
    }

    @Test
    fun latencyLevelsSearchAndOrder() {
        val ms = { n: Long -> com.dpsmpx.dppass.network.LatencyResult.Measured(n) }
        assertEquals(LatencyLevel.GOOD, LatencyLabel.of(ms(80)).level)
        assertEquals(LatencyLevel.FAIR, LatencyLabel.of(ms(150)).level)
        assertEquals(LatencyLevel.POOR, LatencyLabel.of(ms(400)).level)
        assertEquals(
            LatencyLevel.FAILED,
            LatencyLabel.of(com.dpsmpx.dppass.network.LatencyResult.Failed(com.dpsmpx.dppass.network.LatencyFailure.TIMEOUT)).level,
        )
        assertEquals(LatencyLevel.UDP, LatencyLabel.of(com.dpsmpx.dppass.network.LatencyResult.NotTcp).level)
        assertEquals(LatencyLevel.UNKNOWN, LatencyLabel.of(null).level)

        val latency = mapOf(reality.id to ms(300), trojanWs.id to ms(40))
        val rows = ServerList.rows(listOf(reality, trojanWs, hy2, ss), { CandidateHealth() }, null, null, 0) { latency[it] }
        assertEquals(listOf("b", "a", "c", "d"), ServerList.byLatency(rows).map { it.id.value }, "измеренные — по возрастанию, остальные — в прежнем порядке")
        assertEquals(listOf("c"), ServerList.filter(rows, "quic").map { it.id.value }, "поиск и по описанию")
        assertEquals(listOf("a", "b", "c", "d"), ServerList.filter(rows, "  ").map { it.id.value })
        assertEquals(listOf("b"), ServerList.filter(rows, "СЕРВЕР B").map { it.id.value }, "без учёта регистра")
    }

    @Test
    fun durationAndSpeed() {
        assertEquals("0:05", Formats.duration(5_400))
        assertEquals("12:34", Formats.duration((12 * 60 + 34) * 1000L))
        assertEquals("1:02:03", Formats.duration((3600 + 2 * 60 + 3) * 1000L))
        assertEquals("0:00", Formats.duration(-1))
        assertEquals("1.5 MB/s", Formats.speed(1536L * 1024, listOf("B", "KB", "MB", "GB", "TB"), Locale.ENGLISH, "/s"))
    }

    @Test
    fun trafficShareDaysLeftAndKind() {
        val day = 24 * 60 * 60_000L
        val s = Subscription(
            SubscriptionId("s1"), "a", SubscriptionSource.Url(Secret("https://a.example.net/s")),
            metadata = SubscriptionMetadata(
                traffic = TrafficInfo(10, 40, 100, (10 * day + 1000) / 1000),
                webPageUrl = "https://a.example.net/page",
                updateIntervalHours = 6,
            ),
        )
        val inline = Subscription(
            SubscriptionId("s2"),
            "b",
            SubscriptionSource.Inline(Secret("trojan://p@198.51.100.1:443")),
            updatePolicy = com.dpsmpx.dppass.subscriptions.UpdatePolicy(null),
        )
        val rows = SubscriptionList.rows(SubscriptionsState(listOf(s, inline), null), ConfigSource.None, 0)
        assertEquals(50, rows[0].usedPercent)
        assertEquals(10L, rows[0].daysLeft)
        assertEquals("https://a.example.net/page", rows[0].pageUrl)
        assertEquals(6, rows[0].providerIntervalHours)
        assertEquals(12 * 60L, rows[0].autoUpdateMinutes)
        assertTrue(rows[1].inline)
        assertNull(rows[1].autoUpdateMinutes)
        assertNull(rows[1].usedPercent)
    }

    @Test
    fun skippedEntriesAreCountedAndPlaced() {
        val s = Subscription(SubscriptionId("s1"), "S", SubscriptionSource.Url(Secret("https://a.example.net/s")))
        val state = SubscriptionsState(listOf(s), null)
        assertNull(SubscriptionList.rows(state, ConfigSource.None, 0).single().skipped, "не разбиралась — ничего не известно")
        assertEquals(3, SubscriptionList.rows(state, ConfigSource.None, 0) { 3 }.single().skipped)
        assertEquals(1, SubscriptionList.entryNumber("entry[0]"))
        assertEquals(12, SubscriptionList.entryNumber("entry[11]"))
        assertNull(SubscriptionList.entryNumber("profiles[0]"))
        assertNull(SubscriptionList.entryNumber(null))
    }
}
