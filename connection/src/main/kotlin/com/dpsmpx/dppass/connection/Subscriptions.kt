package com.dpsmpx.dppass.connection

import com.dpsmpx.dppass.config.ConfigIr
import com.dpsmpx.dppass.core.Clock
import com.dpsmpx.dppass.core.Ids
import com.dpsmpx.dppass.core.ProfileId
import com.dpsmpx.dppass.core.SubscriptionId
import com.dpsmpx.dppass.diagnostics.DiagCode
import com.dpsmpx.dppass.diagnostics.Diagnostic
import com.dpsmpx.dppass.diagnostics.Outcome
import com.dpsmpx.dppass.diagnostics.Secret
import com.dpsmpx.dppass.diagnostics.map
import com.dpsmpx.dppass.storage.BlobStore
import com.dpsmpx.dppass.storage.Quarantine
import com.dpsmpx.dppass.subscriptions.DeviceId
import com.dpsmpx.dppass.subscriptions.FetchPolicy
import com.dpsmpx.dppass.subscriptions.InlineSubscriptionFetcher
import com.dpsmpx.dppass.subscriptions.SourceFetcher
import com.dpsmpx.dppass.subscriptions.Subscription
import com.dpsmpx.dppass.subscriptions.SubscriptionCodec
import com.dpsmpx.dppass.subscriptions.SubscriptionFetcher
import com.dpsmpx.dppass.subscriptions.SubscriptionSource
import com.dpsmpx.dppass.subscriptions.SubscriptionUpdater
import com.dpsmpx.dppass.subscriptions.SubscriptionsState
import com.dpsmpx.dppass.subscriptions.UpdateResult
import com.dpsmpx.dppass.subscriptions.UpdateSchedule

/**
 * Хранение подписок одной записью `subscriptions/state` (D-36):
 * атомарно (от [BlobStore]), в зашифрованном хранилище на устройстве
 * (D-19). Не прочиталось — исходник уходит в карантин, а не затирается.
 */
class SubscriptionBook(private val blobs: BlobStore, private val quarantine: Quarantine) {
    fun load(): Outcome<SubscriptionsState> {
        val bytes = when (val r = blobs.read(KEY)) {
            is Outcome.Failure -> return r
            is Outcome.Success -> r.value ?: return Outcome.Success(SubscriptionsState.EMPTY)
        }
        return when (val parsed = SubscriptionCodec.read(String(bytes, Charsets.UTF_8))) {
            is Outcome.Success -> parsed
            is Outcome.Failure -> when (val kept = quarantine.keep("subscriptions", bytes, parsed.errors.first())) {
                is Outcome.Failure -> Outcome.Failure(
                    listOf(
                        Diagnostic.error(DiagCode.STORAGE_CORRUPTED, "подписки не прочитаны и не сохранены в карантин")
                            .copy(causes = parsed.diagnostics + kept.diagnostics),
                    ),
                )
                is Outcome.Success -> Outcome.Success(
                    SubscriptionsState.EMPTY,
                    listOf(
                        Diagnostic.warning(DiagCode.STORAGE_CORRUPTED, "подписки не прочитаны; исходник сохранён в карантин, начато с пустого")
                            .copy(causes = parsed.diagnostics),
                    ),
                )
            }
        }
    }

    fun save(state: SubscriptionsState): Outcome<Unit> = blobs.write(KEY, SubscriptionCodec.write(state).toByteArray(Charsets.UTF_8))

    companion object {
        const val KEY: String = "subscriptions/state"
    }
}

/**
 * Записи последнего разобранного ответа поставщика, которые не стали
 * серверами (этап 4, «Объяснимость»): запись не разобрана
 * (`SUBSCRIPTION_ENTRY_SKIPPED`, причина — в `causes`) или ядро её не
 * выражает (`PROFILE_EXCLUDED_UNSUPPORTED`). В сообщениях — имена серверов и
 * параметров, не ссылки. Только в памяти процесса: формат хранения подписок
 * не меняется (D-06); после перезапуска список появится со следующим
 * обновлением.
 */
data class SkippedEntries(val atMillis: Long, val entries: List<Diagnostic>) {
    companion object {
        val CODES: Set<DiagCode> = setOf(DiagCode.SUBSCRIPTION_ENTRY_SKIPPED, DiagCode.PROFILE_EXCLUDED_UNSUPPORTED)

        /**
         * Из итога обновления. Тело разобрано — его пропуски (и пустой список,
         * если пропусков нет); тело не менялось или не загрузилось — null:
         * прежний список остаётся в силе. Отказ, при котором тело разобрано
         * (все записи пропущены), — тоже пропуски.
         */
        fun of(update: UpdateResult, atMillis: Long): SkippedEntries? {
            val entries = update.diagnostics.filter { it.code in CODES }
            return when (update) {
                is UpdateResult.Ready -> SkippedEntries(atMillis, entries)
                is UpdateResult.Unchanged -> null
                is UpdateResult.Failed -> if (entries.isEmpty()) null else SkippedEntries(atMillis, entries)
            }
        }
    }
}

/**
 * Итог обновления подписки: что вернул конвейер и, если дошло, как прошла
 * активация; [before] и [after] — активная конфигурация до и после.
 */
data class SubscriptionRun(
    val subscription: Subscription,
    val update: UpdateResult,
    val activation: ActivationResult?,
    val before: ConfigIr? = null,
    val after: ConfigIr? = null,
    /** Находки слоя подключения о самом ответе: профиль поставщика не разобран (D-94). */
    val notes: List<Diagnostic> = emptyList(),
) {
    val applied: Boolean get() = activation is ActivationResult.Activated
    val diagnostics: List<Diagnostic> get() = update.diagnostics + notes + activation?.diagnostics.orEmpty()

    /**
     * Нужно ли переподключать поднятый туннель (D-39): только если новые
     * серверы применены, а подключённого сервера больше нет или он
     * изменился. Неизменный сервер — соединения не рвутся.
     */
    fun needsReconnect(connected: ProfileId?): Boolean {
        if (!applied || connected == null) return false
        val now = after?.profile(connected) ?: return true
        return before?.profile(connected) != now
    }
}

/**
 * Подписки в приложении (D-36): список, добавление, идентификатор
 * устройства (D-33), обновление с активацией. Состояние читается один
 * раз и дальше меняется только через запись: что не сохранено, того нет.
 */
class SubscriptionService(
    private val book: SubscriptionBook,
    private val core: DPpassCore,
    private val clock: Clock,
) {
    @Volatile
    private var cached: SubscriptionsState? = null

    /** Пропущенные записи последнего разбора каждой подписки — в памяти процесса ([SkippedEntries]). */
    private val skipped = java.util.concurrent.ConcurrentHashMap<SubscriptionId, SkippedEntries>()

    /** Что из последнего разобранного ответа поставщика не стало серверами; null — в этом запуске не разбирался. */
    fun skipped(id: SubscriptionId): SkippedEntries? = skipped[id]

    fun state(): Outcome<SubscriptionsState> = cached?.let { Outcome.Success(it) } ?: book.load().also { r ->
        if (r is Outcome.Success) cached = r.value
    }

    private fun commit(next: SubscriptionsState): Outcome<SubscriptionsState> = when (val w = book.save(next)) {
        is Outcome.Failure -> w
        is Outcome.Success -> Outcome.Success(next.also { cached = it })
    }

    /**
     * Новая подписка по адресу `https://…`. Ничего не загружает: это делает
     * [refresh]. Без имени — имя по хосту адреса.
     */
    fun add(url: String, name: String?): Outcome<Subscription> {
        val trimmed = url.trim()
        if (!isSubscriptionUrl(trimmed)) {
            return Outcome.failure(DiagCode.SUBSCRIPTION_FETCH_FAILED, URL_RULE)
        }
        val given = name?.let(::cleanName)?.takeIf { it.isNotEmpty() }
        if (given != null && !isValidName(given)) return invalidName()
        return insert(given ?: hostOf(trimmed), SubscriptionSource.Url(Secret(trimmed)), byUser = given != null)
    }

    /**
     * «Свои серверы» (D-42): ссылки или их список в base64, вставленные
     * пользователем. Хранятся как тело подписки и разбираются тем же
     * конвейером без сети; [refresh] применяет их.
     */
    fun addInline(body: String, name: String): Outcome<Subscription> {
        val text = body.trim()
        if (text.isEmpty()) return Outcome.failure(DiagCode.SUBSCRIPTION_EMPTY, "нечего добавить: текст пуст")
        if (text.toByteArray(Charsets.UTF_8).size > FetchPolicy().maxBytes) {
            return Outcome.failure(DiagCode.SUBSCRIPTION_TOO_LARGE, "больше ${FetchPolicy().maxBytes} байт")
        }
        val given = cleanName(name)
        val n = given.ifEmpty { "DPpass" }
        if (!isValidName(n)) return invalidName()
        // Без сети обновлять нечего: автообновление своим серверам не нужно.
        return insert(n, SubscriptionSource.Inline(Secret(text)), autoUpdate = false, byUser = given.isNotEmpty())
    }

    private fun insert(name: String, source: SubscriptionSource, autoUpdate: Boolean = true, byUser: Boolean): Outcome<Subscription> {
        val current = when (val s = state()) {
            is Outcome.Failure -> return s
            is Outcome.Success -> s.value
        }
        if (current.items.size >= MAX_SUBSCRIPTIONS) {
            return Outcome.failure(DiagCode.LIMIT_EXCEEDED, "подписок больше $MAX_SUBSCRIPTIONS")
        }
        val n = (current.items.mapNotNull { it.id.value.removePrefix("s").toIntOrNull() }.maxOrNull() ?: 0) + 1
        val id = SubscriptionId("s$n").also { require(Ids.isValid(it.value)) }
        val base = Subscription(id, name, source, nameByUser = byUser)
        val sub = if (autoUpdate) base else base.copy(updatePolicy = base.updatePolicy.copy(intervalMinutes = null))
        return commit(current.copy(items = current.items + sub)).map { sub }
    }

    fun rename(id: SubscriptionId, name: String): Outcome<SubscriptionsState> {
        val n = cleanName(name)
        if (n.isEmpty() || !isValidName(n)) return invalidName()
        // Переименование — выбор пользователя: с ним название поставщика больше не показывается (D-53).
        return edit { st -> st.copy(items = st.items.map { if (it.id == id) it.copy(name = n, nameByUser = true) else it }) }
    }

    /** Срок автообновления (D-39): null — только вручную. */
    fun setUpdateInterval(id: SubscriptionId, minutes: Long?): Outcome<SubscriptionsState> = edit { st ->
        st.copy(items = st.items.map { if (it.id == id) it.copy(updatePolicy = it.updatePolicy.copy(intervalMinutes = minutes)) else it })
    }

    fun remove(id: SubscriptionId): Outcome<SubscriptionsState> = edit { st ->
        st.copy(items = st.items.filter { it.id != id }, activeId = st.activeId?.takeIf { it != id })
    }.also { if (it is Outcome.Success) skipped.remove(id) }

    /** Идентификатор устройства для этой подписки (D-33): включить — новое случайное значение, выключить — забыть. */
    fun setDeviceId(id: SubscriptionId, enabled: Boolean): Outcome<SubscriptionsState> = edit { st ->
        st.copy(items = st.items.map { if (it.id == id) it.copy(deviceId = if (enabled) it.deviceId ?: DeviceId.generate() else null) else it })
    }

    /** Сброс: новое случайное значение; для поставщика это новое устройство (D-33). */
    fun resetDeviceId(id: SubscriptionId): Outcome<SubscriptionsState> = edit { st ->
        st.copy(items = st.items.map { if (it.id == id && it.deviceId != null) it.copy(deviceId = DeviceId.generate()) else it })
    }

    private fun edit(change: (SubscriptionsState) -> SubscriptionsState): Outcome<SubscriptionsState> = when (val s = state()) {
        is Outcome.Failure -> s
        is Outcome.Success -> commit(change(s.value))
    }

    /**
     * Загрузить и применить подписку: её серверы становятся серверами
     * активной конфигурации, маршрутизация и DNS — своего документа, если он
     * действует, иначе политики пользователя (D-38). Подписка, которая
     * сейчас не применена, загружается заново, даже если тело не
     * изменилось: её серверов нигде, кроме ответа поставщика, нет. Свои
     * серверы (D-42) разбираются без сети.
     */
    suspend fun refresh(id: SubscriptionId, fetcher: SubscriptionFetcher, appVersion: String): Outcome<SubscriptionRun> {
        val st = when (val s = state()) {
            is Outcome.Failure -> return s
            is Outcome.Success -> s.value
        }
        val sub = st.find(id) ?: return Outcome.failure(DiagCode.SUBSCRIPTION_FETCH_FAILED, "нет подписки $id")
        val forUpdate = if (st.activeId == id) sub else sub.copy(lastSuccessful = null)
        val source = SourceFetcher(network = fetcher, inline = InlineSubscriptionFetcher(clock))
        val update = SubscriptionUpdater(source, clock, appVersion).update(forUpdate, core.profileFilter())
        core.subscriptionNotes(update)
        SkippedEntries.of(update, clock.nowMillis())?.let { skipped[id] = it }
        val before = core.activation.state.activeConfig
        val notes = mutableListOf<Diagnostic>()
        val (next, activation) = when (update) {
            is UpdateResult.Ready -> {
                val c = update.candidate
                // Профиль поставщика (D-94) принимается с ревизией; не разобран — остаются прежние списки.
                val parsed = c.providerProfile?.let(core::parseProviderProfile)
                if (parsed is Outcome.Failure) {
                    notes += Diagnostic.warning(
                        DiagCode.SUBSCRIPTION_METADATA_INVALID,
                        "routing: профиль маршрутизации поставщика не разобран — списки поставщика остались прежними",
                    ).copy(causes = parsed.errors)
                }
                val withProfile = c.subscription.withProviderProfile(c.providerProfile.takeIf { parsed is Outcome.Success }, c.revision.fetchedAtMillis)
                // Маршрутизация и DNS — своего документа, если он действует, иначе — политики
                // (D-38) со списками поставщика этой подписки, если они включены (D-94).
                val base = core.userPolicy.baseFor(core.activation.state, core.providerListsOf(withProfile))
                val (s, a) = core.activateSubscription(base, c.copy(subscription = withProfile))
                when (a) {
                    is ActivationResult.Activated -> s.copy(lastCheckedMillis = clock.nowMillis())
                    // Ревизия не применена — и профиль её не принят (D-08).
                    is ActivationResult.Rejected -> s.copy(providerProfile = sub.providerProfile, previousProviderProfile = sub.previousProviderProfile)
                } to a
            }
            is UpdateResult.Unchanged -> update.subscription.copy(lastCheckedMillis = clock.nowMillis()) to null
            is UpdateResult.Failed -> update.subscription to null
        }
        // Неудача не стирает прошлую удачную ревизию (D-08): у переданной копии её могло не быть.
        val kept = if (next.lastSuccessful == null) next.copy(lastSuccessful = sub.lastSuccessful) else next
        val activeId = if (activation is ActivationResult.Activated) id else st.activeId
        val saved = commit(st.copy(items = st.items.map { if (it.id == id) kept else it }, activeId = activeId))
        if (saved is Outcome.Failure) return saved
        notes.forEach(core.log::diagnostic)
        return Outcome.Success(SubscriptionRun(kept, update, activation, before, core.activation.state.activeConfig, notes))
    }

    /**
     * Списки поставщика у подписки [id] — включить или выключить (D-94).
     * Включает пользователь, увидев, что в них (D-11: окно подтверждения —
     * в оболочке); дальше они обновляются вместе с подпиской. Подписка
     * применена — смена политики с новыми списками: отказ активации — отказ
     * смены, согласие не записывается.
     */
    suspend fun setUseProviderLists(id: SubscriptionId, use: Boolean): Outcome<ActivationResult?> {
        val st = when (val s = state()) {
            is Outcome.Failure -> return s
            is Outcome.Success -> s.value
        }
        val sub = st.find(id) ?: return Outcome.failure(DiagCode.SUBSCRIPTION_FETCH_FAILED, "нет подписки $id")
        if (sub.useProviderLists == use) return Outcome.Success(null)
        val next = sub.copy(useProviderLists = use)
        val result = if (core.appliedSubscription()?.id == id) {
            when (val r = core.userPolicy.change(core.userPolicy.currentOrDefault(), core.providerListsOf(next))) {
                is Outcome.Failure -> return r
                is Outcome.Success -> r.value.also { if (it is ActivationResult.Rejected) return r }
            }
        } else {
            null
        }
        return commit(st.copy(items = st.items.map { if (it.id == id) next else it })).map { result }
    }

    /**
     * Фоновое обновление (D-39): только применённая подписка и только если
     * пора ([UpdateSchedule.due]). null — обновлять нечего.
     */
    suspend fun refreshDue(fetcher: SubscriptionFetcher, appVersion: String): Outcome<SubscriptionRun>? {
        val st = state().valueOrNull() ?: return null
        val active = st.activeId?.let(st::find) ?: return null
        if (active.source !is SubscriptionSource.Url || !UpdateSchedule.due(active, clock.nowMillis())) return null
        return refresh(active.id, fetcher, appVersion)
    }

    /** Ближайший срок фонового обновления, мс от сейчас; null — автообновления нет. */
    fun nextDueMillis(): Long? {
        val st = state().valueOrNull() ?: return null
        val active = st.activeId?.let(st::find)?.takeIf { it.source is SubscriptionSource.Url } ?: return null
        return UpdateSchedule.waitMillis(active, clock.nowMillis())
    }

    companion object {
        const val MAX_URL: Int = 2048
        const val MAX_NAME: Int = 64
        const val MAX_SUBSCRIPTIONS: Int = 64

        /** Что не так с адресом, который не [isSubscriptionUrl], — для отказа и для импорта. */
        const val URL_RULE: String = "адрес подписки — только https:// без пробелов и управляющих символов, до $MAX_URL символов"

        /** Без пробелов и управляющих символов: из адреса берётся имя подписки по умолчанию. */
        fun isSubscriptionUrl(text: String): Boolean =
            text.startsWith("https://") && text.length in 9..MAX_URL && text.none { it.isWhitespace() || it.isISOControl() }

        private fun hostOf(url: String): String =
            url.removePrefix("https://").substringBefore('/').substringBefore('?').substringAfterLast('@').take(MAX_NAME)

        // Одно правило имени для добавления, «своих серверов» и переименования:
        // без краевых пробелов, не длиннее MAX_NAME, без управляющих символов —
        // имя видно в списке, в уведомлении и в журнале.
        private fun cleanName(name: String): String = name.trim().take(MAX_NAME)

        private fun isValidName(name: String): Boolean = name.none { it.isISOControl() }

        private fun <T> invalidName(): Outcome<T> = Outcome.failure(DiagCode.NAME_INVALID, "имя пустое или с управляющими символами")
    }
}
