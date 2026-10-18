package com.dpsmpx.dppass.subscriptions

import com.dpsmpx.dppass.config.ServerProfile
import com.dpsmpx.dppass.core.SubscriptionId
import com.dpsmpx.dppass.diagnostics.Diagnostic
import com.dpsmpx.dppass.diagnostics.Outcome
import com.dpsmpx.dppass.diagnostics.Secret
import java.security.SecureRandom

/**
 * Подписка — версионированный объект (D-08). Неизменяем: обновление
 * создаёт новый объект целиком, и хранилище заменяет его атомарно, так
 * что состояния «частично обновлённая подписка» не бывает.
 */
data class Subscription(
    val id: SubscriptionId,
    val name: String,
    val source: SubscriptionSource,
    val fetchPolicy: FetchPolicy = FetchPolicy(),
    val updatePolicy: UpdatePolicy = UpdatePolicy(),
    /** Что из подписки берётся: только серверы или ещё и маршрутизация поставщика. */
    val binding: RoutingBinding = RoutingBinding.USER_ROUTING,
    val metadata: SubscriptionMetadata = SubscriptionMetadata(),
    val lastSuccessful: SubscriptionRevision? = null,
    val lastFailed: FailedRevision? = null,
    /** Счётчик ревизий: растёт на каждой удачной загрузке с изменениями. */
    val revisionCounter: Long = 0,
    /**
     * Идентификатор для лимита устройств поставщика (`x-hwid`, D-33):
     * null — не отправляется (по умолчанию). Включает только пользователь;
     * значение — [DeviceId.generate], своё у каждой подписки.
     */
    val deviceId: Secret? = null,
    /**
     * Когда источник последний раз ответил без отказа — с изменениями или
     * без (`Unchanged`). По нему — срок автообновления (D-39): неизменённое
     * тело не двигает удачную ревизию, но проверкой считается.
     */
    val lastCheckedMillis: Long? = null,
    /**
     * Имя задал пользователь — при добавлении или переименованием (D-53).
     * Тогда оно и показывается; иначе — название поставщика
     * (`profile-title`), если оно есть.
     */
    val nameByUser: Boolean = false,
) {
    /**
     * Имя на экранах — одно для списка, экрана подключения и окна
     * переименования (D-53): выбор пользователя поставщик не перебивает
     * (D-11), а имя по умолчанию (хост адреса) уступает его названию.
     */
    val displayName: String
        get() = if (nameByUser) name else metadata.title?.takeIf { it.isNotBlank() } ?: name

    fun recordSuccess(revision: SubscriptionRevision, metadata: SubscriptionMetadata): Subscription =
        copy(lastSuccessful = revision, metadata = metadata, revisionCounter = revision.number)

    fun recordFailure(failure: FailedRevision): Subscription = copy(lastFailed = failure)
}

/** Откуда тело подписки. */
sealed interface SubscriptionSource {
    /** Адрес подписки — секрет: в нём обычно токен доступа. */
    data class Url(val url: Secret) : SubscriptionSource

    /**
     * «Свои серверы» (D-42): ссылки или их список, которые пользователь
     * вставил сам. Тело хранится как есть (секрет: в ссылках — ключи) и
     * разбирается тем же конвейером, без сети.
     */
    data class Inline(val body: Secret) : SubscriptionSource
}

/**
 * Случайный идентификатор подписки для лимита устройств поставщика
 * (D-33). Не из устройства: идентификаторов системы и железа DPpass не
 * читает (D-12). У каждой подписки свой, поэтому поставщики не свяжут
 * подписки одного пользователя; сброс — новое значение.
 */
object DeviceId {
    /** Что принимает Remnawave в `x-hwid`: 10–64 символа латиницы, цифр, «=» и «-». */
    val FORMAT: Regex = Regex("[A-Za-z0-9=-]{10,64}")

    /** 128 случайных бит — 32 шестнадцатеричные цифры (D-21: случайность криптографическая). */
    fun generate(random: SecureRandom = SecureRandom()): Secret {
        val bytes = ByteArray(16).also(random::nextBytes)
        return Secret(bytes.joinToString("") { "%02x".format(it.toInt() and 0xff) })
    }
}

/**
 * Всё, что уходит поставщику в запросе подписки, — и ничего больше
 * (D-12, D-33): адрес, собственный `User-Agent`, одинаковый у всех
 * установок одной версии, и `x-hwid` — только если пользователь включил
 * его для этой подписки. Модели и ОС устройства в запросе нет.
 * Загрузчик (этап 3) переводит это в заголовки один к одному.
 */
data class SubscriptionRequest(val source: SubscriptionSource, val userAgent: String, val deviceId: Secret?) {
    companion object {
        const val DEVICE_ID_HEADER: String = "x-hwid"

        fun of(subscription: Subscription, appVersion: String): SubscriptionRequest = SubscriptionRequest(
            subscription.source,
            "DPpass/$appVersion",
            // У своих серверов поставщика нет — идентификатор некому отправлять.
            subscription.deviceId.takeIf { subscription.source is SubscriptionSource.Url },
        )
    }
}

/**
 * Как загружать: тайм-аут и пределы. Что отправляется поставщику —
 * [SubscriptionRequest].
 */
data class FetchPolicy(
    val timeoutMillis: Long = 20_000,
    val maxBytes: Int = 2 shl 20,
    val maxEntries: Int = 1000,
)

data class UpdatePolicy(
    /** Интервал автообновления (D-39); null — только вручную. */
    val intervalMinutes: Long? = DEFAULT_INTERVAL_MINUTES,
    val onlyUnmetered: Boolean = false,
) {
    companion object {
        const val DEFAULT_INTERVAL_MINUTES: Long = 12 * 60

        /** Что предлагает интерфейс: выкл, 6, 12, 24 часа. */
        val CHOICES_MINUTES: List<Long?> = listOf(null, 6 * 60, 12 * 60, 24 * 60)
    }
}

/**
 * Когда пора обновлять подписку в фоне (D-39). Решает ядро, а не
 * Android: правило одно и проверяется на хосте.
 */
object UpdateSchedule {
    /** После неудачи — не чаще, чем раз в 30 минут: поставщик мог лечь надолго. */
    const val RETRY_AFTER_FAILURE_MILLIS: Long = 30 * 60_000

    fun due(s: Subscription, nowMillis: Long): Boolean {
        val interval = s.updatePolicy.intervalMinutes ?: return false
        val failedAt = s.lastFailed?.failedAtMillis
        val checkedAt = s.lastCheckedMillis ?: s.lastSuccessful?.fetchedAtMillis
        if (failedAt != null && (checkedAt == null || failedAt >= checkedAt) && nowMillis - failedAt < RETRY_AFTER_FAILURE_MILLIS) return false
        return checkedAt == null || nowMillis - checkedAt >= interval * 60_000
    }

    /** Сколько ждать до срока (0 — пора; null — автообновление выключено). */
    fun waitMillis(s: Subscription, nowMillis: Long): Long? {
        val interval = s.updatePolicy.intervalMinutes ?: return null
        val checkedAt = s.lastCheckedMillis ?: s.lastSuccessful?.fetchedAtMillis ?: return 0
        return (checkedAt + interval * 60_000 - nowMillis).coerceAtLeast(0)
    }
}

enum class RoutingBinding {
    /** Маршрутизация и DNS — пользователя; из подписки — только серверы (по умолчанию). */
    USER_ROUTING,

    /** Пользователь явно разрешил брать маршрутизацию и DNS поставщика (D-11). */
    PROVIDER_ROUTING,
}

data class TrafficInfo(val uploadBytes: Long?, val downloadBytes: Long?, val totalBytes: Long?, val expireEpochSeconds: Long?)

/** Информационные метаданные: показываются, но не меняют поведение клиента. */
data class SubscriptionMetadata(
    val title: String? = null,
    val updateIntervalHours: Int? = null,
    val traffic: TrafficInfo? = null,
    val supportUrl: String? = null,
    val webPageUrl: String? = null,
    val announce: String? = null,
)

data class SubscriptionRevision(
    val number: Long,
    val checksum: String,
    val fetchedAtMillis: Long,
    val profileCount: Int,
)

data class FailedRevision(val checksum: String?, val failedAtMillis: Long, val reason: Diagnostic)

/** Ответ источника. Заголовки — с именами в нижнем регистре. */
data class FetchedPayload(val bytes: ByteArray, val headers: Map<String, String>, val fetchedAtMillis: Long) {
    override fun equals(other: Any?): Boolean =
        other is FetchedPayload && other.bytes.contentEquals(bytes) && other.headers == headers && other.fetchedAtMillis == fetchedAtMillis

    override fun hashCode(): Int = bytes.contentHashCode() * 31 + headers.hashCode()
}

/**
 * Загрузка. По сети — `HttpsSubscriptionFetcher` (D-36); свои серверы —
 * `InlineSubscriptionFetcher` (D-42); в тестах и `cli` — из памяти или
 * файла.
 */
fun interface SubscriptionFetcher {
    suspend fun fetch(request: SubscriptionRequest, policy: FetchPolicy): Outcome<FetchedPayload>
}

/**
 * Фильтр серверов по возможностям ядра; реализует `connection/` поверх
 * `engine/`. [paths] — место каждого профиля в теле подписки
 * ([DecodedPayload.paths]): путь находок фильтра.
 */
fun interface ProfileFilter {
    fun filter(profiles: List<ServerProfile>, paths: List<String>): FilterResult
}

data class FilterResult(val usable: List<ServerProfile>, val notes: List<Diagnostic>)
