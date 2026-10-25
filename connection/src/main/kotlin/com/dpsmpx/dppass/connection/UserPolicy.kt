package com.dpsmpx.dppass.connection

import com.dpsmpx.dppass.config.ConfigIr
import com.dpsmpx.dppass.core.Json
import com.dpsmpx.dppass.core.JsonArray
import com.dpsmpx.dppass.core.JsonBool
import com.dpsmpx.dppass.core.JsonNumber
import com.dpsmpx.dppass.core.JsonObject
import com.dpsmpx.dppass.core.JsonParseException
import com.dpsmpx.dppass.core.JsonString
import com.dpsmpx.dppass.core.RuleId
import com.dpsmpx.dppass.diagnostics.DiagCode
import com.dpsmpx.dppass.diagnostics.Diagnostic
import com.dpsmpx.dppass.diagnostics.Outcome
import com.dpsmpx.dppass.routing.AppPolicy
import com.dpsmpx.dppass.routing.Conditions
import com.dpsmpx.dppass.routing.DnsPolicy
import com.dpsmpx.dppass.routing.DnsRoute
import com.dpsmpx.dppass.routing.DnsRule
import com.dpsmpx.dppass.routing.DnsServer
import com.dpsmpx.dppass.routing.DnsTransport
import com.dpsmpx.dppass.routing.RouteAction
import com.dpsmpx.dppass.routing.RoutingPolicy
import com.dpsmpx.dppass.routing.RoutingValidator
import com.dpsmpx.dppass.routing.Rule
import com.dpsmpx.dppass.routing.SiteEntry
import com.dpsmpx.dppass.routing.SiteList
import com.dpsmpx.dppass.routing.SiteListKind
import com.dpsmpx.dppass.routing.SiteLists
import com.dpsmpx.dppass.storage.BlobStore
import com.dpsmpx.dppass.storage.Quarantine

/** Режим маршрутизации политики пользователя (D-38, D-45). */
enum class RoutingMode(val wire: String) {
    /** Всё через туннель, кроме локальных сетей (если включено). */
    ALL_TUNNEL("all_tunnel"),

    /** Российские сайты и адреса — мимо туннеля, их имена — системным резолвером. */
    RU_DIRECT("ru_direct"),

    /**
     * Автоматический раздельный маршрут (D-45, рекомендуемый): как
     * [RU_DIRECT], но с запасным правилом `automatic_domestic` — любое
     * отечественное назначение идёт напрямую само, без выбора сайтов и
     * приложений.
     */
    AUTO("auto"),
}

/** Кто идёт в туннель (D-09, D-38). */
enum class AppMode(val wire: String) { ALL("all"), EXCEPT("except"), ONLY("only") }

/**
 * DoH через туннель по IP-адресу (D-38): имя самого резолвера резолвить
 * нечем, а у этих серверов адрес IP — в сертификате.
 */
enum class DnsProvider(val wire: String, val url: String) {
    CLOUDFLARE("cloudflare", "https://1.1.1.1/dns-query"),
    GOOGLE("google", "https://8.8.8.8/dns-query"),
    QUAD9("quad9", "https://9.9.9.9/dns-query"),
}

/**
 * Политика пользователя (D-38): из неё строятся маршрутизация и DNS
 * активной конфигурации, если пользователь не задал своих документом
 * DPpass. По умолчанию — как базовая политика D-36: всё через туннель,
 * локальные сети мимо него, DoH Cloudflare через туннель.
 */
data class UserPolicy(
    val mode: RoutingMode = RoutingMode.ALL_TUNNEL,
    val blockAds: Boolean = false,
    val bypassLan: Boolean = true,
    val appMode: AppMode = AppMode.ALL,
    /** Пакеты для [AppMode.EXCEPT] и [AppMode.ONLY]; при [AppMode.ALL] хранятся, но не действуют. */
    val apps: Set<String> = emptySet(),
    val dns: DnsProvider = DnsProvider.CLOUDFLARE,
    /** Свои списки сайтов (D-93): напрямую, через туннель, блокировать — раньше правил режима. */
    val lists: SiteLists = SiteLists.NONE,
    /**
     * Свои списки действуют (D-94): выключенные хранятся, но правил не дают —
     * их можно включить снова, не набирая заново.
     */
    val listsEnabled: Boolean = true,
) {
    companion object {
        val DEFAULT: UserPolicy = UserPolicy()
        const val MAX_APPS: Int = 1000
    }
}

/**
 * Политика → маршрутизация и DNS (D-38). Детерминирована; правила —
 * с постоянными id, чтобы объяснение решений называло их одинаково.
 */
object PolicyBuilder {
    const val DNS_REMOTE: String = "remote"
    const val DNS_LOCAL: String = "local"
    const val RULE_ADS: String = "policy-ads"
    const val RULE_RU_SITES: String = "policy-ru-sites"
    const val RULE_RU_IP: String = "policy-ru-ip"

    /** Списки набора геоданных (D-27): есть в dlc и DB-IP; компилятор сверяет их с набором. */
    const val GEOSITE_ADS: String = "category-ads-all"
    const val GEOSITE_RU: String = "category-ru"
    const val GEOIP_RU: String = "ru"

    /** Проверка политики: только выбранные — хотя бы одно приложение (иначе VpnService пустил бы в туннель все). */
    fun validate(p: UserPolicy): List<Diagnostic> {
        val out = mutableListOf<Diagnostic>()
        if (p.appMode == AppMode.ONLY && p.apps.isEmpty()) {
            out += Diagnostic.error(
                DiagCode.APP_POLICY_CONFLICT,
                "«только выбранные приложения» без единого приложения: туннель не для кого",
                "policy.apps",
            )
        }
        if (p.apps.size > UserPolicy.MAX_APPS) {
            out += Diagnostic.error(DiagCode.LIMIT_EXCEEDED, "приложений в политике больше ${UserPolicy.MAX_APPS}", "policy.apps")
        }
        for (pkg in p.apps.filterNot(RoutingValidator::isValidPackage)) {
            out += Diagnostic.error(DiagCode.PACKAGE_INVALID, "не имя пакета Android: ${pkg.take(64)}", "policy.apps")
        }
        out += p.lists.validate(LISTS_PATH)
        return out
    }

    /** Путь находок своих списков: настройка, а не поле документа (D-05). */
    const val LISTS_PATH: String = "policy.lists"

    /** Постоянный id правила своего списка: по имени (`…-sites`) или по адресу (`…-ip`). */
    fun ownRule(kind: SiteListKind, names: Boolean): String = "own-${kind.wire}-${if (names) "sites" else "ip"}"

    /** Правила своих списков (D-93): блокировать, через туннель, напрямую; по имени и по адресу — отдельно (у правила это И). */
    fun ownRules(lists: SiteLists): List<Rule> = listRules(lists, ::ownRule)

    /** Постоянный id правила списка поставщика (D-94): как у своего, с другим началом. */
    fun providerRule(kind: SiteListKind, names: Boolean): String = "provider-${kind.wire}-${if (names) "sites" else "ip"}"

    /** Правила списков поставщика (D-94) — в том же порядке, что свои. */
    fun providerRules(lists: SiteLists): List<Rule> = listRules(lists, ::providerRule)

    private fun listRules(lists: SiteLists, id: (SiteListKind, Boolean) -> String): List<Rule> = SiteLists.ORDER.flatMap { kind ->
        val list = lists[kind]
        listOfNotNull(
            list.names()?.let { Rule(RuleId(id(kind, true)), it, kind.action) },
            list.addresses()?.let { Rule(RuleId(id(kind, false)), it, kind.action) },
        )
    }

    /** Свои списки, если они включены (D-94). */
    private fun own(p: UserPolicy): SiteLists = if (p.listsEnabled) p.lists else SiteLists.NONE

    /** Выбор приложений (D-38; свой выбор без сервера — D-73) → уровень VpnService. */
    fun apps(mode: AppMode, packages: Set<String>): AppPolicy = when (mode) {
        AppMode.ALL -> AppPolicy.AllApps
        AppMode.EXCEPT -> if (packages.isEmpty()) AppPolicy.AllApps else AppPolicy.ExceptApps(packages)
        AppMode.ONLY -> AppPolicy.OnlyApps(packages)
    }

    /** Отечественное идёт напрямую: явными правилами (RU_DIRECT) или автосплитом (AUTO). */
    private fun domesticDirect(p: UserPolicy): Boolean = p.mode == RoutingMode.RU_DIRECT || p.mode == RoutingMode.AUTO

    /**
     * [provider] — списки поставщика применённой подписки, если пользователь
     * их включил (D-94): после своих — свои настройки поверх поставщика, —
     * но раньше рекламы и режима.
     */
    fun routing(p: UserPolicy, provider: SiteLists = SiteLists.NONE): RoutingPolicy {
        // Свои списки (D-93) — первыми: выбор пользователя сильнее режима и поставщика (D-94).
        val rules = ownRules(own(p)).toMutableList()
        rules += providerRules(provider)
        // Реклама — следом: и на российских сайтах тоже.
        if (p.blockAds) rules += Rule(RuleId(RULE_ADS), Conditions(geoSites = listOf(GEOSITE_ADS)), RouteAction.BLOCK)
        if (p.mode == RoutingMode.RU_DIRECT) {
            // Явные правила: отечественное напрямую до любых запасных.
            rules += Rule(RuleId(RULE_RU_SITES), Conditions(geoSites = listOf(GEOSITE_RU)), RouteAction.DIRECT)
            rules += Rule(RuleId(RULE_RU_IP), Conditions(geoIps = listOf(GEOIP_RU)), RouteAction.DIRECT)
        }
        // AUTO (D-45): отечественное уводит напрямую запасное правило автосплита,
        // само, без выбора сайтов и приложений.
        return RoutingPolicy(
            rules = rules,
            defaultAction = RouteAction.PROXY,
            apps = apps(p.appMode, p.apps),
            bypassLan = p.bypassLan,
            automaticDomestic = p.mode == RoutingMode.AUTO,
        )
    }

    /**
     * DNS: всё — DoH выбранного резолвера через туннель. В режимах
     * [RoutingMode.RU_DIRECT] и [RoutingMode.AUTO] российские имена —
     * системному резолверу мимо туннеля: соединение с ними и так идёт мимо
     * туннеля, а ответ зарубежного резолвера указывал бы на зарубежные узлы CDN.
     */
    fun dns(p: UserPolicy, provider: SiteLists = SiteLists.NONE): DnsPolicy {
        val remote = DnsServer(DNS_REMOTE, DnsTransport.Https(p.dns.url), DnsRoute.TUNNEL)
        // Свои списки (D-93): имена «напрямую» — системному резолверу (соединение и так мимо
        // туннеля); имена «через туннель» — резолверу через туннель, даже если они российские.
        // Списки поставщика (D-94) — так же, после своих: первое правило решает.
        val layers = listOf(own(p), provider).map { it.proxy.names() to it.direct.names() }
        val local = domesticDirect(p) || layers.any { it.second != null }
        if (!local) return DnsPolicy(servers = listOf(remote), defaultServerId = DNS_REMOTE)
        val rules = layers.flatMap { (proxy, direct) ->
            listOfNotNull(
                proxy?.let { DnsRule(it.domains, it.geoSites, DNS_REMOTE) },
                direct?.let { DnsRule(it.domains, it.geoSites, DNS_LOCAL) },
            )
        } + listOfNotNull(if (domesticDirect(p)) DnsRule(emptyList(), listOf(GEOSITE_RU), DNS_LOCAL) else null)
        return DnsPolicy(
            servers = listOf(remote, DnsServer(DNS_LOCAL, DnsTransport.System, DnsRoute.DIRECT)),
            defaultServerId = DNS_REMOTE,
            rules = rules,
        )
    }

    /** Те же серверы — с маршрутизацией и DNS политики и списками поставщика [provider] (D-94). */
    fun apply(base: ConfigIr, p: UserPolicy, provider: SiteLists = SiteLists.NONE): ConfigIr =
        base.copy(routing = routing(p, provider), dns = dns(p, provider))

    /** Конфигурация без серверов — основа для подписки. */
    fun ir(p: UserPolicy, provider: SiteLists = SiteLists.NONE): ConfigIr =
        ConfigIr(name = null, profiles = emptyList(), routing = routing(p, provider), dns = dns(p, provider))
}

/**
 * Политика — одна запись `settings/policy` (D-38), документ
 * `dppass.policy` версии 3 (свои списки, D-93; их переключатель, D-94;
 * версии 1 и 2 читаются) в
 * зашифрованном хранилище (D-19). Чтение
 * строгое: не тот формат, неизвестное значение, неверный пакет — порча,
 * исходник уходит в карантин, а не затирается.
 */
class PolicyStore(private val blobs: BlobStore, private val quarantine: Quarantine) {
    fun load(): Outcome<UserPolicy> {
        val bytes = when (val r = blobs.read(KEY)) {
            is Outcome.Failure -> return r
            is Outcome.Success -> r.value ?: return Outcome.Success(UserPolicy.DEFAULT)
        }
        return when (val parsed = PolicyCodec.read(String(bytes, Charsets.UTF_8))) {
            is Outcome.Success -> parsed
            is Outcome.Failure -> when (val kept = quarantine.keep("policy", bytes, parsed.errors.first())) {
                is Outcome.Failure -> Outcome.Failure(
                    listOf(
                        Diagnostic.error(DiagCode.STORAGE_CORRUPTED, "политика не прочитана и не сохранена в карантин")
                            .copy(causes = parsed.diagnostics + kept.diagnostics),
                    ),
                )
                is Outcome.Success -> Outcome.Success(
                    UserPolicy.DEFAULT,
                    listOf(
                        Diagnostic.warning(DiagCode.STORAGE_CORRUPTED, "политика не прочитана; исходник сохранён в карантин, взята политика по умолчанию")
                            .copy(causes = parsed.diagnostics),
                    ),
                )
            }
        }
    }

    fun save(p: UserPolicy): Outcome<Unit> = blobs.write(KEY, PolicyCodec.write(p).toByteArray(Charsets.UTF_8))

    companion object {
        const val KEY: String = "settings/policy"
    }
}

object PolicyCodec {
    const val FORMAT: String = "dppass.policy"

    /**
     * 2 — свои списки сайтов (D-93); 3 — их переключатель (D-94). Версия 1
     * читается как политика без списков, 2 — со включёнными списками.
     */
    const val VERSION: Int = 3
    val READABLE: Set<Int> = setOf(1, 2, 3)

    fun write(p: UserPolicy): String = Json.write(
        Json.obj(
            "format" to Json.str(FORMAT),
            "format_version" to Json.num(VERSION),
            "mode" to Json.str(p.mode.wire),
            "block_ads" to Json.bool(p.blockAds),
            "bypass_lan" to Json.bool(p.bypassLan),
            "apps" to Json.obj("mode" to Json.str(p.appMode.wire), "packages" to Json.strings(p.apps.sorted())),
            "dns" to Json.str(p.dns.wire),
            "lists" to Json.obj(*SiteLists.ORDER.map { k -> k.wire to Json.strings(p.lists[k].entries.map { it.text }) }.toTypedArray()),
            "lists_enabled" to Json.bool(p.listsEnabled),
        ),
        pretty = false,
    )

    fun read(text: String): Outcome<UserPolicy> {
        val root = try {
            Json.parse(text) as? JsonObject
        } catch (e: JsonParseException) {
            null
        } ?: return Outcome.failure(DiagCode.STORAGE_CORRUPTED, "политика — не объект JSON")
        fun bad(what: String): Outcome<UserPolicy> = Outcome.failure(DiagCode.STORAGE_CORRUPTED, "политика: $what")
        val version = (root["format_version"] as? JsonNumber)?.toIntOrNull()
        if ((root["format"] as? JsonString)?.value != FORMAT || version !in READABLE) {
            return Outcome.failure(DiagCode.FORMAT_VERSION_UNSUPPORTED, "неизвестный формат политики")
        }
        val known = setOf("format", "format_version", "mode", "block_ads", "bypass_lan", "apps", "dns") + when (version) {
            1 -> emptySet()
            2 -> setOf("lists")
            else -> setOf("lists", "lists_enabled")
        }
        root.fields.keys.firstOrNull { it !in known }?.let { return bad("неизвестное поле «$it»") }
        val mode = RoutingMode.entries.firstOrNull { it.wire == (root["mode"] as? JsonString)?.value } ?: return bad("mode")
        val ads = (root["block_ads"] as? JsonBool)?.value ?: return bad("block_ads")
        val lan = (root["bypass_lan"] as? JsonBool)?.value ?: return bad("bypass_lan")
        val apps = root["apps"] as? JsonObject ?: return bad("apps")
        val appMode = AppMode.entries.firstOrNull { it.wire == (apps["mode"] as? JsonString)?.value } ?: return bad("apps.mode")
        val packages = (apps["packages"] as? JsonArray)?.items?.map { (it as? JsonString)?.value ?: return bad("apps.packages") } ?: return bad("apps.packages")
        val dns = DnsProvider.entries.firstOrNull { it.wire == (root["dns"] as? JsonString)?.value } ?: return bad("dns")
        var lists = SiteLists.NONE
        if (version != 1) {
            val o = root["lists"] as? JsonObject ?: return bad("lists")
            o.fields.keys.firstOrNull { k -> SiteListKind.entries.none { it.wire == k } }?.let { return bad("lists: неизвестный список «$it»") }
            for (kind in SiteListKind.entries) {
                val items = (o[kind.wire] as? JsonArray)?.items ?: return bad("lists.${kind.wire}")
                val entries = items.map { item ->
                    val text = (item as? JsonString)?.value ?: return bad("lists.${kind.wire}")
                    SiteEntry.parse(text).valueOrNull()?.takeIf { it.text == text } ?: return bad("lists.${kind.wire}: запись не в нормальной форме")
                }
                lists = lists.with(kind, SiteList(entries))
            }
        }
        val listsEnabled = if (version == 3) (root["lists_enabled"] as? JsonBool)?.value ?: return bad("lists_enabled") else true
        val p = UserPolicy(mode, ads, lan, appMode, packages.toSet(), dns, lists, listsEnabled)
        val problems = PolicyBuilder.validate(p).filter { it.isError }
        if (problems.isNotEmpty()) {
            return Outcome.Failure(listOf(Diagnostic.error(DiagCode.STORAGE_CORRUPTED, "политика не прошла проверку").copy(causes = problems)))
        }
        return Outcome.Success(p)
    }
}

/**
 * Политика в приложении (D-38): чтение (один раз), смена и применение к
 * действующим серверам. Смена — транзакция D-07: политика записывается,
 * только если активация с ней прошла (или активировать нечего).
 */
class PolicyService(private val store: PolicyStore, private val core: DPpassCore) {
    @Volatile
    private var cached: UserPolicy? = null

    fun current(): Outcome<UserPolicy> = cached?.let { Outcome.Success(it) } ?: store.load().also { r ->
        if (r is Outcome.Success) cached = r.value
    }

    /** Политика без отказа хранилища: при нём — по умолчанию (интерфейс показывает причину отдельно). */
    fun currentOrDefault(): UserPolicy = current().valueOrNull() ?: UserPolicy.DEFAULT

    /**
     * Новая политика. Если есть активная конфигурация — её серверы
     * активируются с новой маршрутизацией и DNS; отказ активации — отказ
     * смены, прежняя политика и конфигурация остаются.
     */
    suspend fun change(next: UserPolicy, provider: SiteLists = core.activeProviderLists()): Outcome<ActivationResult?> {
        val problems = PolicyBuilder.validate(next)
        if (problems.any { it.isError }) return Outcome.Failure(problems)
        val active = core.activation.state
        val config = active.activeConfig
        val record = active.active
        val result = if (config != null && record != null && config.profiles.isNotEmpty()) {
            val ir = PolicyBuilder.apply(config, next, provider)
            val r = core.activation.activate(ir, record.source, record.sourceChecksum)
            core.logActivation(r)
            if (r is ActivationResult.Rejected) return Outcome.Success(r)
            r
        } else {
            null
        }
        return when (val w = store.save(next)) {
            is Outcome.Failure -> w
            is Outcome.Success -> Outcome.Success(result.also { cached = next })
        }
    }

    /**
     * Свои списки из текста правки (D-93): [texts] — новые тексты списков,
     * прочие остаются. Неверная строка, запись в двух списках или код
     * geosite/geoip, которого нет в наборе ядра (D-27), — отказ до смены
     * политики, с номером строки.
     */
    suspend fun setSiteLists(texts: Map<SiteListKind, String>): Outcome<ActivationResult?> {
        var lists = currentOrDefault().lists
        val problems = mutableListOf<Diagnostic>()
        for ((kind, text) in texts) {
            when (val r = SiteList.parse(text, "${PolicyBuilder.LISTS_PATH}.${kind.wire}")) {
                is Outcome.Failure -> problems += r.errors
                is Outcome.Success -> lists = lists.with(kind, r.value)
            }
        }
        if (problems.isNotEmpty()) return Outcome.Failure(problems)
        return changeLists(lists)
    }

    /** Добавить списки импорта (профиль Happ, D-93) к своим: та же запись из другого своего списка переезжает. */
    suspend fun addSiteLists(add: SiteLists): Outcome<ActivationResult?> = changeLists(currentOrDefault().lists.merge(add))

    private suspend fun changeLists(lists: SiteLists): Outcome<ActivationResult?> {
        val problems = lists.validate(PolicyBuilder.LISTS_PATH) + core.checkSiteLists(lists)
        if (problems.any { it.isError }) return Outcome.Failure(problems.filter { it.isError })
        return change(currentOrDefault().copy(lists = lists))
    }

    /** Свои списки включить или выключить (D-94): списки хранятся, меняется только, действуют ли они. */
    suspend fun setListsEnabled(enabled: Boolean): Outcome<ActivationResult?> = change(currentOrDefault().copy(listsEnabled = enabled))

    /**
     * Основа для подписки: своя маршрутизация из документа, если она
     * действует, иначе — политика со списками поставщика [provider] (D-94).
     */
    fun baseFor(state: ActivationState, provider: SiteLists = core.activeProviderLists()): ConfigIr {
        val config = state.activeConfig
        return if (config != null && state.active?.source == OWN_DOCUMENT) config else PolicyBuilder.ir(currentOrDefault(), provider)
    }

    companion object {
        /** Источник записи активации у своего документа (`DPpassCore.importAndActivate`). */
        const val OWN_DOCUMENT: String = "user-import"
    }
}
