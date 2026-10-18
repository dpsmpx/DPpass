package com.dpsmpx.dppass.subscriptions

import com.dpsmpx.dppass.config.ConfigValidator
import com.dpsmpx.dppass.config.CountRange
import com.dpsmpx.dppass.config.Hysteria2Congestion
import com.dpsmpx.dppass.config.ProtocolSpec
import com.dpsmpx.dppass.config.SecuritySpec
import com.dpsmpx.dppass.config.ShadowsocksMethod
import com.dpsmpx.dppass.config.TlsFingerprint
import com.dpsmpx.dppass.config.TransportSpec
import com.dpsmpx.dppass.config.VlessFlow
import com.dpsmpx.dppass.config.XHttpExtra
import com.dpsmpx.dppass.config.XHttpMode
import com.dpsmpx.dppass.config.Xmux
import com.dpsmpx.dppass.core.ManualClock
import com.dpsmpx.dppass.core.SubscriptionId
import com.dpsmpx.dppass.diagnostics.DiagCode
import com.dpsmpx.dppass.diagnostics.Outcome
import com.dpsmpx.dppass.diagnostics.Secret
import kotlinx.coroutines.runBlocking
import java.lang.reflect.Modifier
import java.util.Base64
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.test.fail

private const val KEY = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"
private const val UUID1 = "00000000-0000-4000-8000-000000000011"

class ShareLinkParserTest {
    @Test
    fun realityVisionLink() {
        val link = "vless://$UUID1@203.0.113.11:443?type=tcp&security=reality&sni=www.example.com&pbk=$KEY&sid=01234567" +
            "&fp=firefox&flow=xtls-rprx-vision&encryption=none#Reality%20NL"
        val p = ShareLinkParser.parse(link, "s").valueOrNull()!!
        assertEquals("Reality NL", p.name)
        assertEquals(VlessFlow.VISION, (p.protocol as ProtocolSpec.Vless).flow)
        val sec = p.security as SecuritySpec.Reality
        assertEquals("www.example.com", sec.serverName)
        assertEquals(KEY, sec.publicKey)
        assertTrue(p.id.value.startsWith("s."))
    }

    @Test
    fun idIsStableAndIgnoresName() {
        val a = ShareLinkParser.parse("vless://$UUID1@203.0.113.11:443?security=tls&sni=a.example.com#One", "s").valueOrNull()!!
        val b = ShareLinkParser.parse("vless://$UUID1@203.0.113.11:443?security=tls&sni=a.example.com#Two", "s").valueOrNull()!!
        assertEquals(a.id, b.id)
    }

    @Test
    fun xhttpAndTrojan() {
        val x = ShareLinkParser.parse("vless://$UUID1@cdn.example.net:443?type=xhttp&security=tls&path=%2Fx&mode=stream-one", "s").valueOrNull()!!
        assertEquals(TransportSpec.XHttp("/x", null, XHttpMode.STREAM_ONE), x.transport)
        val t = ShareLinkParser.parse("trojan://pass@198.51.100.1:443?sni=t.example.org", "s").valueOrNull()!!
        assertIs<SecuritySpec.Tls>(t.security)
        assertEquals(Secret("pass"), (t.protocol as ProtocolSpec.Trojan).password)
    }

    @Test
    fun namesAreNormalizedLikeDocumentAndEmptyMeansAbsent() {
        val p = ShareLinkParser.parse(
            "vless://$UUID1@cdn.example.net:443?type=ws&security=tls&sni=CDN.Example.NET.&host=CDN.Example.NET&path=%2Fws",
            "s",
        ).valueOrNull()!!
        assertEquals("cdn.example.net", (p.security as SecuritySpec.Tls).serverName)
        assertEquals(TransportSpec.WebSocket("/ws", "cdn.example.net"), p.transport)
        val empty = ShareLinkParser.parse("trojan://pass@198.51.100.1:443?sni=&type=ws&host=", "s").valueOrNull()!!
        assertNull((empty.security as SecuritySpec.Tls).serverName)
        assertEquals(TransportSpec.WebSocket("/", null), empty.transport)
    }

    @Test
    fun invalidNamesReachProfileValidation() {
        // Разбор ссылки неверное имя не чинит и не прячет: его отвергает проверка профиля с путём (D-05).
        val sni = ShareLinkParser.parse("trojan://pass@198.51.100.1:443?sni=bad%20name.example.org", "s").valueOrNull()!!
        assertEquals(listOf(DiagCode.SERVER_NAME_INVALID), ConfigValidator.validateProfile(sni, "profiles[0]").map { it.code })
        val host = ShareLinkParser.parse("trojan://pass@198.51.100.1:443?sni=t.example.org&type=ws&host=bad%20host.example.org", "s").valueOrNull()!!
        assertEquals(listOf(DiagCode.DOMAIN_INVALID), ConfigValidator.validateProfile(host, "profiles[0]").map { it.code })
    }

    @Test
    fun emptyPathAndServiceNameMeanAbsent() {
        val ws = ShareLinkParser.parse("trojan://pass@198.51.100.1:443?sni=t.example.org&type=ws&path=", "s").valueOrNull()!!
        assertEquals(TransportSpec.WebSocket("/", null), ws.transport)
        val grpc = ShareLinkParser.parse("trojan://pass@198.51.100.1:443?sni=t.example.org&type=grpc&serviceName=", "s")
        assertEquals(DiagCode.SHARE_LINK_INVALID, grpc.errors.single().code)
    }

    @Test
    fun invalidPathAndServiceNameReachProfileValidation() {
        for (link in listOf(
            "trojan://pass@198.51.100.1:443?sni=t.example.org&type=ws&path=no-slash",
            "trojan://pass@198.51.100.1:443?sni=t.example.org&type=httpupgrade&path=%2Fa%20b",
            "vless://$UUID1@198.51.100.1:443?security=tls&sni=t.example.org&type=xhttp&path=x",
            "trojan://pass@198.51.100.1:443?sni=t.example.org&type=grpc&serviceName=bad%20name",
        )) {
            val p = ShareLinkParser.parse(link, "s").valueOrNull()!!
            assertEquals(listOf(DiagCode.PATH_INVALID), ConfigValidator.validateProfile(p, "profiles[0]").map { it.code }, link)
        }
    }

    @Test
    fun unknownParameterMakesLinkUnusableExplicitly() {
        val r = ShareLinkParser.parse("vless://$UUID1@203.0.113.1:443?security=tls&xyz=1", "s")
        val e = r.errors.single()
        assertEquals(DiagCode.SHARE_LINK_INVALID, e.code)
        assertEquals(DiagCode.SHARE_LINK_PARAM_UNSUPPORTED, e.causes.single().code)
        assertTrue("xyz" in e.causes.single().message)
    }

    private fun unsupportedNames(r: Outcome<*>): String {
        val e = r.errors.single()
        assertEquals(DiagCode.SHARE_LINK_INVALID, e.code)
        return e.causes.single { it.code == DiagCode.SHARE_LINK_PARAM_UNSUPPORTED }.message
    }

    @Test
    fun hysteria2Link() {
        val link = "hysteria2://test-password-2@192.0.2.30:8443/?sni=hy2.example.com&obfs=salamander&obfs-password=test-obfs-1#HY2"
        val p = ShareLinkParser.parse(link, "s").valueOrNull()!!
        val proto = assertIs<ProtocolSpec.Hysteria2>(p.protocol)
        assertEquals("test-password-2", proto.password.reveal())
        assertEquals("test-obfs-1", proto.obfsPassword?.reveal())
        assertEquals(TransportSpec.Native, p.transport)
        assertEquals(SecuritySpec.Tls("hy2.example.com", emptyList(), null), p.security)
        assertEquals("HY2", p.name)
        assertTrue(ConfigValidator.validateProfile(p, "p").none { it.isError })
        // hy2:// — то же самое; без obfs — без Salamander.
        val short = ShareLinkParser.parse("hy2://test-password-2@192.0.2.30:8443?sni=hy2.example.com", "s").valueOrNull()!!
        assertEquals(null, (short.protocol as ProtocolSpec.Hysteria2).obfsPassword)
    }

    @Test
    fun hysteria2RejectsWhatIrCannotExpress() {
        val base = "hysteria2://test-password-2@192.0.2.30:8443/?sni=hy2.example.com"
        // Маски finalmask (кроме quicParams.congestion, D-37) и pinSHA256 (пиннинг) IR не выражает.
        assertTrue("pinsha256" in unsupportedNames(ShareLinkParser.parse("$base&pinSHA256=AA", "s")))
        assertTrue("fm.udp" in unsupportedNames(ShareLinkParser.parse("$base&fm=%7B%22udp%22%3A%5B%5D%7D", "s")))
        val obfs = unsupportedNames(ShareLinkParser.parse("$base&obfs=gecko&obfs-password=x", "s"))
        assertTrue("obfs" in obfs && "gecko" !in obfs, obfs)
        assertEquals(DiagCode.INSECURE_TLS_REJECTED, ShareLinkParser.parse("$base&insecure=1", "s").errors.single().code)
        assertTrue(ShareLinkParser.parse("$base&insecure=0", "s").isSuccess)
        for (bad in listOf("$base&obfs=salamander", "$base&obfs-password=x", "hysteria2://test-password-2@192.0.2.30:443,8443/?sni=hy2.example.com")) {
            assertEquals(DiagCode.SHARE_LINK_INVALID, ShareLinkParser.parse(bad, "s").errors.single().code, bad)
        }
    }

    @Test
    fun shadowsocks2022LinkInEveryUserinfoForm() {
        val key = "AAECAwQFBgcICQoLDA0ODw=="
        val plain = "2022-blake3-aes-128-gcm:$key"
        val forms = listOf(
            Base64.getEncoder().encodeToString(plain.toByteArray()),
            Base64.getUrlEncoder().withoutPadding().encodeToString(plain.toByteArray()),
            "2022-blake3-aes-128-gcm:" + key.replace("=", "%3D"),
        )
        for (userinfo in forms) {
            val p = ShareLinkParser.parse("ss://$userinfo@192.0.2.40:8388#SS", "s").valueOrNull() ?: fail(userinfo)
            val proto = assertIs<ProtocolSpec.Shadowsocks>(p.protocol)
            assertEquals(ShadowsocksMethod.BLAKE3_AES_128_GCM to key, proto.method to proto.password.reveal(), userinfo)
            assertEquals(TransportSpec.Tcp to SecuritySpec.None, p.transport to p.security)
            assertTrue(ConfigValidator.validateProfile(p, "p").none { it.isError }, userinfo)
        }
    }

    @Test
    fun shadowsocksLegacyMethodsAndPluginsAreExplicitlyUnsupported() {
        val legacy = Base64.getEncoder().encodeToString("chacha20-ietf-poly1305:test-password-3".toByteArray())
        assertTrue("D-16" in unsupportedNames(ShareLinkParser.parse("ss://$legacy@192.0.2.40:8388#Old", "s")))
        val key = Base64.getEncoder().encodeToString("2022-blake3-aes-128-gcm:AAECAwQFBgcICQoLDA0ODw==".toByteArray())
        assertTrue("plugin" in unsupportedNames(ShareLinkParser.parse("ss://$key@192.0.2.40:8388?plugin=obfs-local#P", "s")))
        assertEquals(DiagCode.SHARE_LINK_INVALID, ShareLinkParser.parse("ss://bm9jb2xvbg@192.0.2.40:8388", "s").errors.single().code)
        // Неизвестный «метод» не повторяется: в испорченной ссылке там бывает секрет.
        val r = ShareLinkParser.parse("ss://test-password-9:x@192.0.2.40:8388", "s")
        assertFalse(r.diagnostics.flatMap { it.renderWithCauses() }.any { "test-password-9" in it }, unsupportedNames(r))
    }

    /**
     * D-48: `fm.quicParams.debug` в Xray только включает отладочный журнал
     * перегрузки во всём процессе — запись не теряется, флаг отбрасывается с
     * находкой. Не true/false — отказ; соседние неизвестные ключи — отказ, как раньше.
     */
    @Test
    fun quicDebugFlagIsDroppedWithNote() {
        val base = "hysteria2://test-password-2@192.0.2.30:8443/?sni=hy2.example.com&fm="
        val r = ShareLinkParser.parse(base + "%7B%22quicParams%22%3A%7B%22congestion%22%3A%22bbr%22%2C%22debug%22%3Atrue%7D%7D", "s")
        val p = r.valueOrNull()!!
        assertEquals(Hysteria2Congestion.BBR, (p.protocol as ProtocolSpec.Hysteria2).congestion)
        val note = r.diagnostics.single()
        assertEquals(DiagCode.SHARE_LINK_PARAM_IGNORED, note.code)
        assertFalse(note.isError)
        assertTrue("fm.quicParams.debug" in note.message, note.message)
        // Только debug — без перегрузки.
        val only = ShareLinkParser.parse(base + "%7B%22quicParams%22%3A%7B%22debug%22%3Afalse%7D%7D", "s")
        assertEquals(null, (only.valueOrNull()!!.protocol as ProtocolSpec.Hysteria2).congestion)
        assertEquals(DiagCode.SHARE_LINK_PARAM_IGNORED, only.diagnostics.single().code)
        assertEquals(
            DiagCode.SHARE_LINK_INVALID,
            ShareLinkParser.parse(base + "%7B%22quicParams%22%3A%7B%22debug%22%3A%22yes%22%7D%7D", "s").errors.single().code,
        )
        val other = unsupportedNames(ShareLinkParser.parse(base + "%7B%22quicParams%22%3A%7B%22debug%22%3Atrue%2C%22disableGSO%22%3Atrue%7D%7D", "s"))
        assertTrue("fm.quicParams.disableGSO" in other && "debug" !in other, other)
    }

    /** Формат 2 (D-37): отпечатки, `extra` XHTTP и `fm` Hysteria2 из ссылок панели. */
    @Test
    fun formatV2LinkParameters() {
        val qq = ShareLinkParser.parse("vless://$UUID1@203.0.113.11:443?security=reality&sni=www.example.com&pbk=$KEY&fp=qq&flow=xtls-rprx-vision", "s")
        assertEquals(TlsFingerprint.QQ, (qq.valueOrNull()!!.security as SecuritySpec.Reality).fingerprint)
        val edge = ShareLinkParser.parse("vless://$UUID1@cdn.example.net:443?type=ws&security=tls&sni=cdn.example.net&path=%2Fws&fp=edge", "s")
        assertEquals(TlsFingerprint.EDGE, (edge.valueOrNull()!!.security as SecuritySpec.Tls).fingerprint)

        val extra = "%7B%22xPaddingBytes%22%3A%22100-1000%22%2C%22noGRPCHeader%22%3Atrue%2C%22xmux%22%3A" +
            "%7B%22maxConcurrency%22%3A%2216-32%22%2C%22maxConnections%22%3A0%2C%22hKeepAlivePeriod%22%3A0%7D%7D"
        val x = ShareLinkParser.parse("vless://$UUID1@203.0.113.26:443?type=xhttp&security=reality&sni=www.example.com&pbk=$KEY&path=%2Fx&extra=$extra", "s")
        val e = (x.valueOrNull()!!.transport as TransportSpec.XHttp).extra
        assertEquals(XHttpExtra(xPaddingBytes = CountRange(100, 1000), noGrpcHeader = true, xmux = Xmux(maxConcurrency = CountRange(16, 32))), e)
        assertTrue(ConfigValidator.validateProfile(x.valueOrNull()!!, "p").none { it.isError })

        val hy2 = ShareLinkParser.parse(
            "hysteria2://test-password-2@192.0.2.30:8443/?sni=hy2.example.com&fm=%7B%22quicParams%22%3A%7B%22congestion%22%3A%22bbr%22%7D%7D",
            "s",
        )
        assertEquals(Hysteria2Congestion.BBR, (hy2.valueOrNull()!!.protocol as ProtocolSpec.Hysteria2).congestion)

        // Незнакомый ключ — отказ с названием, без значения.
        val headers = unsupportedNames(
            ShareLinkParser.parse(
                "vless://$UUID1@203.0.113.26:443?type=xhttp&security=tls&sni=a.example.com&extra=%7B%22headers%22%3A%7B%22x%22%3A%22secret-9%22%7D%7D",
                "s",
            ),
        )
        assertTrue("extra.headers" in headers && "secret-9" !in headers, headers)
        val brutal = unsupportedNames(
            ShareLinkParser.parse("hysteria2://test-password-2@192.0.2.30:8443/?fm=%7B%22quicParams%22%3A%7B%22congestion%22%3A%22brutal%22%7D%7D", "s"),
        )
        assertTrue("congestion" in brutal, brutal)
        // extra у другого транспорта и не-JSON — отказ.
        assertTrue("extra" in unsupportedNames(ShareLinkParser.parse("vless://$UUID1@203.0.113.1:443?security=tls&sni=a.example.com&extra=%7B%7D", "s")))
        assertEquals(
            DiagCode.SHARE_LINK_INVALID,
            ShareLinkParser.parse("vless://$UUID1@203.0.113.1:443?type=xhttp&security=tls&sni=a.example.com&extra=nope", "s").errors.single().code,
        )
        // Оба предела xmux — ссылка разбирается, профиль отвергает проверка (как у документа).
        val both = ShareLinkParser.parse(
            "vless://$UUID1@203.0.113.1:443?type=xhttp&security=tls&sni=a.example.com&extra=%7B%22xmux%22%3A%7B%22maxConcurrency%22%3A2%2C%22maxConnections%22%3A3%7D%7D",
            "s",
        )
        assertEquals(listOf(DiagCode.TRANSPORT_SETTING_INVALID), ConfigValidator.validateProfile(both.valueOrNull()!!, "p").map { it.code })
    }

    @Test
    fun insecureIsRejected() {
        val r = ShareLinkParser.parse("vless://$UUID1@203.0.113.1:443?security=tls&allowInsecure=1", "s")
        assertEquals(DiagCode.INSECURE_TLS_REJECTED, r.errors.single().code)
    }

    @Test
    fun malformedLinksNeverThrowAndNeverEchoSecrets() {
        val malformed = listOf(
            "vless://",
            "vless://@:",
            "vless://$UUID1@[::1:443",
            "vless://$UUID1@h:99999",
            "vless://$UUID1@h:443?a=%zz",
            "vless://$UUID1@h:443?a=1&a=2",
            "nonsense",
        )
        for (bad in malformed) {
            val r = ShareLinkParser.parse(bad, "s")
            assertIs<Outcome.Failure>(r, bad)
            assertFalse(r.diagnostics.any { UUID1 in it.message }, bad)
        }
    }
}

class MetadataParserTest {
    @Test
    fun blankValuesMeanNotSet() {
        // Так Remnawave присылает незаполненные поля: пустой заголовок — не ошибка и не директива.
        val r = MetadataParser.parse(
            mapOf("support-url" to "", "profile-update-interval" to " ", "subscription-userinfo" to "", "routing" to "", "hide-settings" to "1"),
            emptyMap(),
        )
        assertTrue(r.notes.none { it.code == DiagCode.SUBSCRIPTION_METADATA_INVALID }, r.notes.joinToString { it.message })
        val ignored = r.notes.single { it.code == DiagCode.SUBSCRIPTION_DIRECTIVE_IGNORED }.message
        assertTrue("hide-settings" in ignored && "routing" !in ignored, ignored)
        assertEquals(SubscriptionMetadata(), r.metadata)
    }

    @Test
    fun safeFieldsApplyControlDirectivesDoNot() {
        val r = MetadataParser.parse(
            mapOf(
                "profile-title" to "base64:0J/RgNC40LzQtdGA",
                "subscription-userinfo" to "upload=1; download=2; total=3; expire=4",
                "new-url" to "https://x.example.com/t",
            ),
            mapOf("hide-settings" to "1", "profile-update-interval" to "6"),
        )
        assertEquals("Пример", r.metadata.title)
        assertEquals(TrafficInfo(1, 2, 3, 4), r.metadata.traffic)
        assertEquals(6, r.metadata.updateIntervalHours)
        val ignored = r.notes.single { it.code == DiagCode.SUBSCRIPTION_DIRECTIVE_IGNORED }
        assertTrue("new-url" in ignored.message && "hide-settings" in ignored.message)
        assertFalse("x.example.com" in ignored.message, "значения директив не попадают в сообщение")
    }

    /** Название поставщика — по тому же правилу, что имя подписки: без управляющих символов, и DEL, и C1. */
    @Test
    fun providerTitleWithControlCharactersIsDropped() {
        for (title in listOf("base64:VlBOwoV4", "base64:VlBOfw==")) {
            val r = MetadataParser.parse(mapOf("profile-title" to title), emptyMap())
            assertNull(r.metadata.title, title)
            assertEquals(1, r.notes.count { it.code == DiagCode.SUBSCRIPTION_METADATA_INVALID }, title)
        }
    }

    @Test
    fun nonHttpsLinksAreNotAccepted() {
        val r = MetadataParser.parse(mapOf("support-url" to "http://support.example.com", "profile-web-page-url" to "javascript:alert(1)"), emptyMap())
        assertNull(r.metadata.supportUrl)
        assertNull(r.metadata.webPageUrl)
        assertEquals(2, r.notes.count { it.code == DiagCode.SUBSCRIPTION_METADATA_INVALID })
    }
}

class SubscriptionUpdaterTest {
    private val clock = ManualClock(1000)
    private val links = "vless://$UUID1@203.0.113.11:443?security=tls&sni=a.example.com#A\ntrojan://p@198.51.100.2:443#B\n"
    private val passAll = ProfileFilter { ps, _ -> FilterResult(ps, emptyList()) }

    private fun sub() = Subscription(SubscriptionId("sub1"), "Sub", SubscriptionSource.Url(Secret("https://sub.example.com/token123")))

    private fun fetcher(body: String) = SubscriptionFetcher { _, _ -> Outcome.Success(FetchedPayload(body.toByteArray(), emptyMap(), clock.nowMillis())) }

    @Test
    fun readyThenUnchanged() = runBlocking {
        val r = SubscriptionUpdater(fetcher(links), clock, "test").update(sub(), passAll)
        val ready = assertIs<UpdateResult.Ready>(r)
        assertEquals(2, ready.candidate.profiles.size)
        val updated = ready.candidate.subscription.recordSuccess(ready.candidate.revision, ready.candidate.metadata)
        val again = SubscriptionUpdater(fetcher(links), clock, "test").update(updated, passAll)
        assertTrue(again is UpdateResult.Unchanged, "ожидалось Unchanged, есть $again")
    }

    /**
     * 6 октября 2026, телефон автора: одна и та же ссылка под двумя именами дала два
     * профиля с одним id; конфигурация активировалась, а при перезапуске не прочиталась
     * (ID_DUPLICATE) и ушла в карантин. Второй профиль с тем же id — пропуск с находкой.
     */
    @Test
    fun sameLinkUnderTwoNamesIsOneServer() = runBlocking {
        val body = "vless://$UUID1@203.0.113.11:443?security=tls&sni=a.example.com#Первый\n" +
            "vless://$UUID1@203.0.113.11:443?security=tls&sni=a.example.com#Второй\n" +
            "trojan://p@198.51.100.2:443#B\n"
        val ready = assertIs<UpdateResult.Ready>(SubscriptionUpdater(fetcher(body), clock, "test").update(sub(), passAll))
        assertEquals(listOf("Первый", "B"), ready.candidate.profiles.map { it.name })
        assertEquals(ready.candidate.profiles.map { it.id }.distinct(), ready.candidate.profiles.map { it.id })
        val skipped = ready.diagnostics.single { it.code == DiagCode.SUBSCRIPTION_ENTRY_SKIPPED }
        assertTrue("Второй" in skipped.message && "Первый" in skipped.message, skipped.message)
        assertEquals(2, ready.candidate.revision.profileCount)
    }

    @Test
    fun failureKeepsLastSuccessfulRevision() = runBlocking {
        val ready = SubscriptionUpdater(fetcher(links), clock, "test").update(sub(), passAll) as UpdateResult.Ready
        val good = ready.candidate.subscription.recordSuccess(ready.candidate.revision, ready.candidate.metadata)
        val r = SubscriptionUpdater(fetcher("<html>oops</html>"), clock, "test").update(good, passAll)
        val failed = assertIs<UpdateResult.Failed>(r)
        assertEquals(good.lastSuccessful, failed.subscription.lastSuccessful)
        assertEquals(DiagCode.SUBSCRIPTION_FORMAT_UNKNOWN, failed.subscription.lastFailed!!.reason.code)
    }

    @Test
    fun filterExclusionsAreExplicit() = runBlocking {
        val onlyTrojan = ProfileFilter { ps, _ ->
            FilterResult(
                ps.filter {
                    it.protocol is ProtocolSpec.Trojan
                },
                listOf(com.dpsmpx.dppass.diagnostics.Diagnostic.warning(DiagCode.PROFILE_EXCLUDED_UNSUPPORTED, "x")),
            )
        }
        val r = SubscriptionUpdater(fetcher(links), clock, "test").update(sub(), onlyTrojan) as UpdateResult.Ready
        assertEquals(1, r.candidate.profiles.size)
        assertTrue(r.diagnostics.any { it.code == DiagCode.PROFILE_EXCLUDED_UNSUPPORTED })
    }

    @Test
    fun findingsOfCheckAndFilterNameTheEntryOfTheBody() = runBlocking {
        // Запись 1 не разобрана, у записи 2 неверное имя TLS, запись 3 исключает фильтр:
        // путь каждой находки — номер записи тела, как у разбора, а не номер среди уцелевших.
        val body = "vless://$UUID1@203.0.113.11:443?security=tls&sni=a.example.com#A\n" +
            "trojan://198.51.100.40:443\n" +
            "trojan://pass@198.51.100.1:443?sni=bad%20name.example.org#Bad\n" +
            "trojan://q@198.51.100.3:443#C\n"
        val given = mutableListOf<String>()
        val noC = ProfileFilter { ps, paths ->
            given += paths
            FilterResult(
                ps.filter { it.name != "C" },
                ps.indices.filter { ps[it].name == "C" }.map {
                    com.dpsmpx.dppass.diagnostics.Diagnostic.warning(DiagCode.PROFILE_EXCLUDED_UNSUPPORTED, "сервер «C» исключён", paths[it])
                },
            )
        }
        val r = SubscriptionUpdater(fetcher(body), clock, "test").update(sub(), noC) as UpdateResult.Ready
        assertEquals(listOf("entry[0]", "entry[3]"), given, "фильтр получает места записей в теле")
        val placed = r.diagnostics
            .filter { it.code == DiagCode.SUBSCRIPTION_ENTRY_SKIPPED || it.code == DiagCode.PROFILE_EXCLUDED_UNSUPPORTED }
            .map { it.code to it.path }
        assertEquals(
            listOf(
                DiagCode.SUBSCRIPTION_ENTRY_SKIPPED to "entry[1]",
                DiagCode.SUBSCRIPTION_ENTRY_SKIPPED to "entry[2]",
                DiagCode.PROFILE_EXCLUDED_UNSUPPORTED to "entry[3]",
            ),
            placed,
        )
    }

    @Test
    fun fetchFailureKeepsCause() = runBlocking {
        val f = SubscriptionFetcher { _, _ -> Outcome.failure(DiagCode.ENDPOINT_UNREACHABLE, "timeout") }
        val r = SubscriptionUpdater(f, clock, "test").update(sub(), passAll) as UpdateResult.Failed
        val reason = r.subscription.lastFailed!!.reason
        assertEquals(DiagCode.SUBSCRIPTION_FETCH_FAILED, reason.code)
        assertEquals(DiagCode.ENDPOINT_UNREACHABLE, reason.causes.single().code)
    }

    /** Заглушка Remnawave при лимите устройств — синтетическая: нулевой UUID на 0.0.0.0. */
    private val placeholder = "vless://00000000-0000-0000-0000-000000000000@0.0.0.0:1?encryption=none&type=tcp&security=none#App%20not%20supported\n"

    private fun recording(sent: MutableList<SubscriptionRequest>, body: String, headers: Map<String, String> = emptyMap()) =
        SubscriptionFetcher { request, _ ->
            sent += request
            Outcome.Success(FetchedPayload(body.toByteArray(), headers, clock.nowMillis()))
        }

    @Test
    fun requestHasNoDeviceIdUnlessEnabled() = runBlocking {
        val sent = mutableListOf<SubscriptionRequest>()
        SubscriptionUpdater(recording(sent, links), clock, "1.2.3").update(sub(), passAll)
        val request = sent.single()
        assertNull(request.deviceId, "без согласия идентификатор не отправляется (D-12, D-33)")
        assertEquals("DPpass/1.2.3", request.userAgent)
        assertEquals(sub().source, request.source)

        val id = DeviceId.generate()
        SubscriptionUpdater(recording(sent, links), clock, "1.2.3").update(sub().copy(deviceId = id), passAll)
        assertEquals(id, sent.last().deviceId)
        // Больше ничего об устройстве в запросе нет: только адрес, User-Agent и идентификатор подписки.
        assertEquals(
            setOf("source", "userAgent", "deviceId"),
            SubscriptionRequest::class.java.declaredFields.filter {
                !Modifier.isStatic(it.modifiers)
            }.map { it.name }.toSet(),
        )
    }

    @Test
    fun deviceIdsAreRandomPerSubscription() {
        val ids = List(200) { DeviceId.generate().reveal() }
        assertEquals(ids.size, ids.toSet().size, "значения повторились")
        for (v in ids) {
            assertTrue(DeviceId.FORMAT.matches(v) && v.length == 32 && v.all { it in "0123456789abcdef" }, "не 32 шестнадцатеричные цифры")
        }
        assertFalse(ids.first() in DeviceId.generate().toString(), "Secret печатает значение")
    }

    @Test
    fun deviceRefusalsAreNamedAndPlaceholderIsNotImported() = runBlocking {
        val ready = SubscriptionUpdater(fetcher(links), clock, "test").update(sub(), passAll) as UpdateResult.Ready
        val good = ready.candidate.subscription.recordSuccess(ready.candidate.revision, ready.candidate.metadata)
        val cases = listOf(
            mapOf("X-Hwid-Active" to "true", "X-Hwid-Not-Supported" to "true") to DiagCode.SUBSCRIPTION_DEVICE_ID_REQUIRED,
            mapOf("x-hwid-active" to "true", "x-hwid-max-devices-reached" to "true") to DiagCode.SUBSCRIPTION_DEVICE_LIMIT_REACHED,
        )
        for ((headers, code) in cases) {
            val r = SubscriptionUpdater(recording(mutableListOf(), placeholder, headers), clock, "test").update(good, passAll)
            val failed = assertIs<UpdateResult.Failed>(r, "$code")
            assertEquals(code, failed.subscription.lastFailed!!.reason.code)
            assertEquals(good.lastSuccessful, failed.subscription.lastSuccessful, "удачная ревизия не тронута (D-08)")
            // Заглушка не разбиралась: ни одной находки о её «сервере».
            assertTrue(failed.diagnostics.none { it.code == DiagCode.SUBSCRIPTION_ENTRY_SKIPPED }, "$code: заглушка разобрана как сервер")
        }
        // С включённым идентификатором — другая подсказка: идентификатор не принят, а не «включите его».
        val withId = good.copy(deviceId = DeviceId.generate())
        val r = SubscriptionUpdater(recording(mutableListOf(), placeholder, cases[0].first), clock, "test").update(withId, passAll) as UpdateResult.Failed
        assertTrue("не принял" in r.subscription.lastFailed!!.reason.message)
    }

    @Test
    fun oversizedPayloadIsRejected() = runBlocking {
        val s = sub().copy(fetchPolicy = FetchPolicy(maxBytes = 10))
        val r = SubscriptionUpdater(fetcher(links), clock, "test").update(s, passAll) as UpdateResult.Failed
        assertEquals(DiagCode.SUBSCRIPTION_TOO_LARGE, r.subscription.lastFailed!!.reason.code)
    }
}

/** Когда пора обновлять подписку в фоне (D-39). */
class UpdateScheduleTest {
    private val hour = 60 * 60_000L
    private val base = Subscription(SubscriptionId("s1"), "S", SubscriptionSource.Url(Secret("https://sub.example.com/t")))
    private fun failure(at: Long) = FailedRevision(null, at, com.dpsmpx.dppass.diagnostics.Diagnostic.error(DiagCode.SUBSCRIPTION_FETCH_FAILED, "x"))

    @Test
    fun intervalsFailuresAndOff() {
        assertTrue(UpdateSchedule.due(base, 0), "ни разу не проверялась — пора")
        val checked = base.copy(lastCheckedMillis = 10 * hour)
        assertFalse(UpdateSchedule.due(checked, 21 * hour))
        assertTrue(UpdateSchedule.due(checked, 22 * hour), "12 часов по умолчанию")
        assertEquals(hour, UpdateSchedule.waitMillis(checked, 21 * hour))
        // После неудачи — не раньше чем через 30 минут.
        val failed = checked.copy(lastFailed = failure(22 * hour))
        assertFalse(UpdateSchedule.due(failed, 22 * hour + 29 * 60_000))
        assertTrue(UpdateSchedule.due(failed, 22 * hour + 30 * 60_000))
        // Удачная ревизия без отметки проверки (версия 1 хранения) — срок от неё.
        val legacy = base.copy(lastSuccessful = SubscriptionRevision(1, "c", 5 * hour, 3))
        assertFalse(UpdateSchedule.due(legacy, 16 * hour))
        assertTrue(UpdateSchedule.due(legacy, 17 * hour))
        // Выключено — никогда.
        val off = checked.copy(updatePolicy = UpdatePolicy(intervalMinutes = null))
        assertFalse(UpdateSchedule.due(off, 1000 * hour))
        assertNull(UpdateSchedule.waitMillis(off, 0))
    }
}

/** Хранение версии 2 (D-39, D-42) и чтение версии 1. */
class SubscriptionCodecTest {
    @Test
    fun inlineSourceIntervalAndCheckRoundTrip() {
        val items = listOf(
            Subscription(SubscriptionId("s1"), "Url", SubscriptionSource.Url(Secret("https://sub.example.com/t")), lastCheckedMillis = 42),
            Subscription(SubscriptionId("s2"), "Мои", SubscriptionSource.Inline(Secret("trojan://p@198.51.100.1:443#A")), updatePolicy = UpdatePolicy(null)),
            Subscription(SubscriptionId("s3"), "Daily", SubscriptionSource.Url(Secret("https://sub.example.com/u")), updatePolicy = UpdatePolicy(24 * 60)),
            Subscription(SubscriptionId("s4"), "Дом", SubscriptionSource.Url(Secret("https://sub.example.com/v")), nameByUser = true),
        )
        val state = SubscriptionsState(items, SubscriptionId("s2"))
        assertEquals(state, SubscriptionCodec.read(SubscriptionCodec.write(state)).valueOrNull())
    }

    @Test
    fun version2ReadsAsNameNotChosenByUser() {
        // До версии 3 признака не было: имя показывается, как показывалось, — название поставщика (D-53).
        val v2 = """{"format":"dppass.subscriptions","format_version":2,"items":[""" +
            """{"id":"s1","name":"Дом","url":"https://sub.example.com/t","binding":"user","revision_counter":0,"metadata":{"title":"Поставщик"}}]}"""
        val s = SubscriptionCodec.read(v2).valueOrNull()!!.items.single()
        assertFalse(s.nameByUser)
        assertEquals("Поставщик", s.displayName)
        assertIs<Outcome.Failure>(SubscriptionCodec.read(v2.replace("\"format_version\":2", "\"format_version\":4")), "версия новее — отказ")
    }

    @Test
    fun displayNameIsUsersChoiceOverProviderTitle() {
        val base = Subscription(SubscriptionId("s1"), "sub.example.com", SubscriptionSource.Url(Secret("https://sub.example.com/t")))
        assertEquals("sub.example.com", base.displayName, "ни имени пользователя, ни названия — имя по адресу")
        val titled = base.copy(metadata = SubscriptionMetadata(title = "Поставщик"))
        assertEquals("Поставщик", titled.displayName, "имя по умолчанию уступает названию поставщика")
        assertEquals("sub.example.com", titled.copy(metadata = SubscriptionMetadata(title = "  ")).displayName, "пустое название — не название")
        assertEquals("Мой", titled.copy(name = "Мой", nameByUser = true).displayName, "выбор пользователя поставщик не перебивает (D-11)")
    }

    @Test
    fun version1ReadsWithDefaults() {
        val v1 = """{"format":"dppass.subscriptions","format_version":1,"items":[""" +
            """{"id":"s1","name":"S","url":"https://sub.example.com/t","binding":"user","revision_counter":0,"metadata":{}}]}"""
        val s = SubscriptionCodec.read(v1).valueOrNull()!!.items.single()
        assertEquals(UpdatePolicy(), s.updatePolicy)
        assertNull(s.lastCheckedMillis)
        // Ровно один источник.
        val both = v1.replace("\"url\":\"https://sub.example.com/t\"", "\"url\":\"https://sub.example.com/t\",\"inline\":\"x\"")
        assertIs<Outcome.Failure>(SubscriptionCodec.read(both))
    }
}

/** Предел записей подписки (docs/PERFORMANCE_BUDGET.md, §2): лишние не читаются, и это видно. */
class PayloadLimitsTest {
    private fun links(n: Int) = (1..n).joinToString("\n") { i ->
        "trojan://test-password-$i@203.0.113.${i % 250 + 1}:443?security=tls&sni=t$i.example.com#T$i"
    }

    @Test
    fun entriesUpToLimitAreReadTheRestAreSkippedLoudly() {
        val max = FetchPolicy().maxEntries
        assertEquals(1000, max, "как в PERFORMANCE_BUDGET §2")
        val exact = PayloadDecoder.decode(links(max).toByteArray(), "s", max).valueOrNull()!!
        assertEquals(max, exact.profiles.size)
        val over = PayloadDecoder.decode(links(max + 5).toByteArray(), "s", max)
        assertEquals(max, over.valueOrNull()!!.profiles.size)
        val skipped = over.diagnostics.single { it.code == DiagCode.SUBSCRIPTION_ENTRY_SKIPPED }
        assertTrue("$max" in skipped.message, skipped.message)
        assertFalse(skipped.isError)
    }
}
