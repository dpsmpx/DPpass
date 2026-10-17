package com.dpsmpx.dppass.connection

import com.dpsmpx.dppass.config.ServerProfile
import com.dpsmpx.dppass.config.TransportClass
import com.dpsmpx.dppass.config.transportClass
import com.dpsmpx.dppass.core.ProfileId
import com.dpsmpx.dppass.diagnostics.Diagnostic
import com.dpsmpx.dppass.network.NetworkAssessment
import com.dpsmpx.dppass.network.NetworkType
import com.dpsmpx.dppass.network.Reachability
import com.dpsmpx.dppass.network.RestrictionClass
import kotlin.math.abs
import kotlin.math.exp
import kotlin.math.max
import kotlin.math.min
import kotlin.math.pow
import kotlin.math.sqrt

/*
 * Адаптивная модель устойчивости (D-44). Клиент учится на исходах своих
 * попыток и проб (D-32), чтобы выбирать кандидата, который в **этой
 * сети** держится стабильнее, и быстро уходить от сервера, который начал
 * сбоить. Устойчивость важнее скорости: порядок множителей в оценке —
 * надёжность, стабильность джиттера, задержка, отсутствие «замерзаний».
 *
 * Это не десинхронизация пакетов (её делает Zapret, ей нужен root —
 * отложенный вопрос): «стратегия» DPpass — выбор кандидата (D-15),
 * параметры сервера не меняются (D-05). Исследование подхода —
 * `docs/research/ZAPRET_ADAPTIVE_METHODS.md`.
 *
 * Детерминизм (D-21): при одних и тех же наблюдениях и времени — один и
 * тот же результат. Время приходит в наблюдении, не из часов.
 */

/** Одно наблюдение по кандидату: исход попытки или пробы здоровья (D-32). */
data class StabilityObservation(
    val success: Boolean,
    /** Время установки/ответа, мс; null — не измерялось. */
    val rttMillis: Long? = null,
    /** «Подключено, но данных нет» (L7, `PAYLOAD_STALLED`). */
    val stalled: Boolean = false,
    val timestampMillis: Long,
)

/**
 * Грубый контекст сети (D-44): только тип сети и класс ограничения.
 * **Ни SSID, ни BSSID, ни адреса, ни оператора, ни идентификатора
 * устройства** (D-12). Опыт привязан к контексту: «в мобильной сети с
 * деградацией» — не то же, что «в домашней норме».
 */
data class NetworkContext(
    val transport: NetworkType,
    val restriction: RestrictionClass,
) {
    /** Строка контекста для ключа записи; без идентификаторов. */
    fun token(): String = transport.name + "~" + restriction.name

    companion object {
        fun of(assessment: NetworkAssessment?): NetworkContext =
            NetworkContext(assessment?.type ?: NetworkType.OTHER, assessment?.restriction ?: RestrictionClass.UNKNOWN)
    }
}

/**
 * Затухающий агрегат по паре «контекст, сервер». Хранит только числа,
 * не трафик. Надёжность — Beta с априором и полураспадом; задержка и её
 * разброс — по RFC 6298 (SRTT, RTTVAR) и RFC 3550 (джиттер); «замерзания»
 * — EWMA; резкий рост отказов — накопитель Пейджа — Хинкли.
 */
data class StabilityStats(
    val alpha: Double = PRIOR,
    val beta: Double = PRIOR,
    val srttMillis: Double = 0.0,
    val rttVarMillis: Double = 0.0,
    val jitterMillis: Double = 0.0,
    val ewmaStall: Double = 0.0,
    val lastRttMillis: Double? = null,
    /** Накопитель Пейджа — Хинкли и его минимум (обнаружение смены режима). */
    val phCusum: Double = 0.0,
    val phMin: Double = 0.0,
    val badStreak: Int = 0,
    val observations: Long = 0,
    val lastUpdatedMillis: Long = 0,
) {
    val hasObservation: Boolean get() = observations > 0

    /** Доля успехов по затухающему Beta. */
    val reliabilityMean: Double get() = alpha / (alpha + beta)

    /**
     * Нижняя граница доверия к доле успехов (пессимизм, D-44): 3 успеха из
     * 3 не обгоняют 95 из 100. Запас — одно стандартное отклонение.
     */
    val reliabilityLcb: Double
        get() {
            val n = alpha + beta
            val m = reliabilityMean
            val sd = sqrt(m * (1 - m) / n)
            return (m - sd).coerceIn(0.0, 1.0)
        }

    /** Признак смены режима: накопитель ушёл выше порога над своим минимумом. */
    val regimeShift: Boolean get() = phCusum - phMin > PH_LAMBDA

    /**
     * Оценка устойчивости [0..1], устойчивость важнее скорости (D-44).
     * Нет наблюдений — нейтрально.
     */
    fun stabilityScore(): Double {
        if (observations == 0L) return NEUTRAL
        val jitter = 1.0 / (1.0 + jitterMillis / JITTER_REF_MILLIS)
        val rtt = if (srttMillis <= 0.0) NEUTRAL else 1.0 / (1.0 + srttMillis / RTT_REF_MILLIS)
        val stall = 1.0 - min(1.0, ewmaStall)
        return (W_RELIABILITY * reliabilityLcb + W_JITTER * jitter + W_RTT * rtt + W_STALL * stall).coerceIn(0.0, 1.0)
    }

    /** Свернуть новое наблюдение: сперва затухание до [sample].timestampMillis. */
    fun fold(sample: StabilityObservation): StabilityStats {
        val decayed = decayTo(sample.timestampMillis)
        val rtt = sample.rttMillis?.coerceIn(1L, MAX_RTT_MILLIS)?.toDouble()
        // SRTT/RTTVAR по RFC 6298; джиттер по RFC 3550 (сглаженная |разность|).
        val nextSrtt: Double
        val nextVar: Double
        val nextJitter: Double
        if (rtt == null) {
            nextSrtt = decayed.srttMillis; nextVar = decayed.rttVarMillis; nextJitter = decayed.jitterMillis
        } else if (decayed.srttMillis <= 0.0) {
            nextSrtt = rtt; nextVar = rtt / 2; nextJitter = decayed.jitterMillis
        } else {
            nextVar = (1 - BETA_RFC) * decayed.rttVarMillis + BETA_RFC * abs(decayed.srttMillis - rtt)
            nextSrtt = (1 - ALPHA_RFC) * decayed.srttMillis + ALPHA_RFC * rtt
            val d = decayed.lastRttMillis?.let { abs(rtt - it) } ?: 0.0
            nextJitter = decayed.jitterMillis + (d - decayed.jitterMillis) / JITTER_GAIN
        }
        val stallValue = if (sample.stalled) 1.0 else 0.0
        val nextStall = decayed.ewmaStall + EWMA_GAIN * (stallValue - decayed.ewmaStall)
        // Пейдж — Хинкли на индикаторе отказа: растёт при учащении отказов.
        val x = if (sample.success) 0.0 else 1.0
        val cusum = decayed.phCusum + (x - PH_BASELINE - PH_DELTA)
        val phMin = min(decayed.phMin, cusum)
        val spiking = rtt != null && decayed.srttMillis > 0 && rtt > decayed.srttMillis + RTT_SPIKE_K * max(decayed.rttVarMillis, 1.0)
        val bad = !sample.success || sample.stalled || spiking
        return decayed.copy(
            alpha = decayed.alpha + if (sample.success) 1.0 else 0.0,
            beta = decayed.beta + if (sample.success) 0.0 else 1.0,
            srttMillis = nextSrtt.coerceIn(0.0, MAX_RTT_MILLIS.toDouble()),
            rttVarMillis = nextVar.coerceIn(0.0, MAX_RTT_MILLIS.toDouble()),
            jitterMillis = nextJitter.coerceIn(0.0, MAX_RTT_MILLIS.toDouble()),
            ewmaStall = nextStall.coerceIn(0.0, 1.0),
            lastRttMillis = rtt ?: decayed.lastRttMillis,
            phCusum = cusum,
            phMin = phMin,
            badStreak = if (bad) (decayed.badStreak + 1).coerceAtMost(MAX_BAD_STREAK) else 0,
            observations = (decayed.observations + 1).coerceAtMost(MAX_OBSERVATIONS),
            lastUpdatedMillis = sample.timestampMillis,
        )
    }

    /** Затухание к априору по полураспаду: старый опыт весит меньше (D-44). */
    fun decayTo(nowMillis: Long): StabilityStats {
        if (observations == 0L || nowMillis <= lastUpdatedMillis) return this
        val d = 0.5.pow((nowMillis - lastUpdatedMillis).toDouble() / HALF_LIFE_MILLIS)
        return copy(
            alpha = PRIOR + (alpha - PRIOR) * d,
            beta = PRIOR + (beta - PRIOR) * d,
            // Накопитель смены режима тоже забывается: давняя тревога снимается.
            phCusum = phCusum * d,
            phMin = phMin * d,
        )
    }

    companion object {
        const val PRIOR = 1.0
        const val NEUTRAL = 0.5
        const val HALF_LIFE_MILLIS = 24L * 60 * 60 * 1000
        const val W_RELIABILITY = 0.55
        const val W_JITTER = 0.25
        const val W_RTT = 0.12
        const val W_STALL = 0.08
        const val JITTER_REF_MILLIS = 40.0
        const val RTT_REF_MILLIS = 250.0
        const val ALPHA_RFC = 1.0 / 8
        const val BETA_RFC = 1.0 / 4
        const val JITTER_GAIN = 16.0
        const val EWMA_GAIN = 0.25
        const val PH_BASELINE = 0.15
        const val PH_DELTA = 0.05
        const val PH_LAMBDA = 2.0
        const val RTT_SPIKE_K = 4.0
        const val MAX_BAD_STREAK = 64
        const val MAX_OBSERVATIONS = 100_000L
        const val MAX_RTT_MILLIS = 60_000L
    }
}

/**
 * Лёгкая модель обобщения (D-44): один слой — логистическая регрессия
 * (нейросеть из одного нейрона) над признаками сети и сервера. Переносит
 * опыт на серверы без своей истории: отказ UDP в сети → ниже оценка всех
 * UDP-кандидатов. Онлайн-SGD, детерминирован, веса ограничены.
 */
class TransportAdvisor(weights: DoubleArray? = null) {
    private val w: DoubleArray = weights?.copyOf(FEATURES) ?: DoubleArray(FEATURES)

    fun weights(): DoubleArray = w.copyOf()

    /** Предсказанная вероятность успеха [0..1]. */
    fun predict(profile: ServerProfile, assessment: NetworkAssessment?): Double = sigmoid(dot(features(profile, assessment)))

    /** Шаг обучения по исходу (target 1 — успех, 0 — отказ). */
    fun learn(profile: ServerProfile, assessment: NetworkAssessment?, success: Boolean) {
        val x = features(profile, assessment)
        val err = sigmoid(dot(x)) - if (success) 1.0 else 0.0
        for (i in w.indices) {
            val grad = err * x[i] + L2 * w[i]
            w[i] = (w[i] - LR * grad).coerceIn(-CLAMP, CLAMP)
        }
    }

    private fun dot(x: DoubleArray): Double {
        var s = 0.0
        for (i in w.indices) s += w[i] * x[i]
        return s
    }

    private fun features(profile: ServerProfile, a: NetworkAssessment?): DoubleArray {
        val x = DoubleArray(FEATURES)
        x[0] = 1.0 // смещение
        when (profile.transportClass) {
            TransportClass.TCP_STREAM -> x[1] = 1.0
            TransportClass.HTTP_CDN -> x[2] = 1.0
            TransportClass.UDP_QUIC -> x[3] = 1.0
            // Не обучается на нём вовсе (StabilityModel.observe); признака класса нет.
            TransportClass.LOCAL_RELAY -> Unit
        }
        x[4] = if (a?.restriction == RestrictionClass.DEGRADED) 1.0 else 0.0
        x[5] = if (a?.restriction == RestrictionClass.ALLOWLIST_LIKE) 1.0 else 0.0
        x[6] = if (a?.tls == Reachability.BLOCKED || a?.tls == Reachability.DEGRADED) 1.0 else 0.0
        x[7] = if (a?.udp == Reachability.BLOCKED) 1.0 else 0.0
        x[8] = if (a?.bulk == Reachability.DEGRADED) 1.0 else 0.0
        return x
    }

    private fun sigmoid(z: Double): Double = 1.0 / (1.0 + exp(-z.coerceIn(-30.0, 30.0)))

    companion object {
        const val FEATURES = 9
        const val LR = 0.05
        const val L2 = 1e-4
        const val CLAMP = 8.0
    }
}

/**
 * Модель устойчивости (D-44): агрегаты по парам «контекст, сервер» плюс
 * обобщение [TransportAdvisor]. Сердце — чистое, без Android и ввода-вывода;
 * хранение — [StabilityBook]. Доступ потокобезопасен (`@Synchronized`):
 * пишет наблюдатель сессии, читает планировщик.
 */
class StabilityModel internal constructor(
    private val records: LinkedHashMap<String, StabilityStats>,
    private val advisor: TransportAdvisor,
) {
    constructor() : this(LinkedHashMap(), TransportAdvisor())

    @Synchronized
    fun observe(
        profileId: ProfileId,
        context: NetworkContext,
        sample: StabilityObservation,
        profile: ServerProfile? = null,
        assessment: NetworkAssessment? = null,
    ) {
        val key = key(profileId, context)
        records[key] = (records[key] ?: StabilityStats()).fold(sample)
        // Исход устройства раздачи (D-55) говорит о своей сети, а не о сети оператора:
        // обобщение по классам на нём не учится — ни в его пользу, ни во вред другим.
        if (profile != null && profile.transportClass != TransportClass.LOCAL_RELAY) advisor.learn(profile, assessment, sample.success)
        trim()
    }

    @Synchronized
    fun stats(profileId: ProfileId, context: NetworkContext): StabilityStats = records[key(profileId, context)] ?: StabilityStats()

    /**
     * Оценка кандидата [0..1] для порядка плана (D-15). Пока наблюдений
     * мало, вес смещается к обобщению [TransportAdvisor]: сервер без своей
     * истории наследует опыт своего класса в этой сети.
     */
    @Synchronized
    fun score(profile: ServerProfile, assessment: NetworkAssessment?): Double {
        val context = NetworkContext.of(assessment)
        val s = recordFor(profile.id, context)
        val statScore = s.stabilityScore()
        val n = s.observations.toDouble()
        val wStat = n / (n + ADVISOR_PRIOR_N)
        val advisorP = advisor.predict(profile, assessment)
        return (wStat * statScore + (1 - wStat) * advisorP).coerceIn(0.0, 1.0)
    }

    /**
     * Пора уходить с кандидата (D-44): подтверждённая деградация с
     * гистерезисом, а не одиночный сбой (T14). Смена режима ускоряет вывод.
     */
    @Synchronized
    fun shouldRecover(profileId: ProfileId, context: NetworkContext): Boolean {
        val s = stats(profileId, context)
        if (!s.hasObservation) return false
        // Череда плохих наблюдений (гистерезис, не один сбой — T14) И либо низкая
        // оценка, либо подтверждённая смена режима (отказы резко участились).
        return s.badStreak >= SWITCH_STREAK && (s.stabilityScore() < RECOVERY_SCORE || s.regimeShift)
    }

    @Synchronized
    fun size(): Int = records.size

    @Synchronized
    internal fun snapshot(): Pair<Map<String, StabilityStats>, DoubleArray> = LinkedHashMap(records) to advisor.weights()

    /**
     * Серверы, которые в контексте [context] чаще отказывали, чем работали
     * (D-64): удача такого сервера под белым списком опровергает сам список.
     */
    @Synchronized
    fun failingIn(context: NetworkContext): Set<ProfileId> {
        val prefix = context.token() + SEP
        return records.entries
            .filter { it.key.startsWith(prefix) && it.value.hasObservation && it.value.reliabilityMean < StabilityStats.NEUTRAL }
            .map { ProfileId(it.key.removePrefix(prefix)) }
            .toSet()
    }

    /**
     * Опыт профиля в этом контексте, иначе самый свежий по этому профилю в
     * любой сети. Под белым списком чужой опыт не переносится (D-64): там
     * закрыто то, что в обычной сети работает, — сервер без опыта под
     * списком судится по обобщению [TransportAdvisor].
     */
    private fun recordFor(profileId: ProfileId, context: NetworkContext): StabilityStats {
        records[key(profileId, context)]?.let { return it }
        if (context.restriction == RestrictionClass.ALLOWLIST_LIKE) return StabilityStats()
        val suffix = SEP + profileId.value
        return records.entries.asSequence()
            .filter { it.key.endsWith(suffix) }
            .maxByOrNull { it.value.lastUpdatedMillis }
            ?.value
            ?: StabilityStats()
    }

    private fun trim() {
        if (records.size <= MAX_RECORDS) return
        records.entries.sortedBy { it.value.lastUpdatedMillis }
            .take(records.size - MAX_RECORDS)
            .forEach { records.remove(it.key) }
    }

    private fun key(profileId: ProfileId, context: NetworkContext): String = context.token() + SEP + profileId.value

    companion object {
        const val MAX_RECORDS = 256
        const val SWITCH_STREAK = 2
        const val RECOVERY_SCORE = 0.45
        const val ADVISOR_PRIOR_N = 4.0
        const val SEP = "|"
    }
}

/**
 * Наблюдатель сессии (D-44): по потоку наблюдений решает «держать или
 * переподключиться». Чистая логика без Android — проверяется на хосте;
 * Android-слой (`DPpassVpnService`) снимает пробу D-32 и передаёт исход.
 *
 * Переключение — с гистерезисом модели и не чаще предела в час: смена
 * сервера сама нагрузка и сигнал фильтру (L7). Один экземпляр на сессию.
 */
class SessionSupervisor(
    private val model: StabilityModel,
    private val profileId: ProfileId,
    private val context: NetworkContext,
    private val maxSwitchesPerHour: Int = 4,
    private val minHoldMillis: Long = 20_000,
) {
    private val switches = ArrayDeque<Long>()
    private var lastSwitchMillis = Long.MIN_VALUE

    enum class Decision { HOLD, RECONNECT }

    /** Свернуть наблюдение и решить. [profile]/[assessment] — для обобщения. */
    fun onObservation(sample: StabilityObservation, profile: ServerProfile? = null, assessment: NetworkAssessment? = null): Decision {
        model.observe(profileId, context, sample, profile, assessment)
        val now = sample.timestampMillis
        while (switches.isNotEmpty() && now - switches.first() >= HOUR_MILLIS) switches.removeFirst()
        if (!model.shouldRecover(profileId, context)) return Decision.HOLD
        // Без переполнения на начальном Long.MIN_VALUE: пока не переключались — пауза не действует.
        if (lastSwitchMillis != Long.MIN_VALUE && now - lastSwitchMillis < minHoldMillis) return Decision.HOLD
        if (switches.size >= maxSwitchesPerHour) return Decision.HOLD
        switches.addLast(now)
        lastSwitchMillis = now
        return Decision.RECONNECT
    }

    private companion object {
        const val HOUR_MILLIS = 60L * 60 * 1000
    }
}

/**
 * Что делать с подтверждённой деградацией сессии (D-58): наблюдатель
 * решил, что сервер перестал держать соединение. [reason] — последняя
 * проваленная проба, её видит пользователь.
 */
sealed interface Degradation {
    val reason: Diagnostic

    /**
     * Переподключиться по плану (D-15): выбран режим «Автоматически»,
     * подключение через устройство раздачи (D-55), замены нет или
     * пользователь уже ответил «Остаться».
     */
    data class Reconnect(override val reason: Diagnostic) : Degradation

    /**
     * Сбоит сервер, выбранный пользователем (D-34): спросить, перейти ли на
     * [to]. Пока ответа нет — переподключение к [from], как прежде.
     */
    data class Ask(val from: ServerProfile, val to: ServerProfile, override val reason: Diagnostic) : Degradation

    /** «Автопереключение» включено — согласие заранее: [to] становится выбранным, пользователю — сообщение. */
    data class Switch(val from: ServerProfile, val to: ServerProfile, override val reason: Diagnostic) : Degradation
}

/** Разбор/запись одного числа модели: короткие, устойчивые к мусору. */
internal object AdaptiveCodec {
    fun double(s: String, default: Double): Double = s.toDoubleOrNull()?.takeIf { it.isFinite() } ?: default
    fun long(s: String, default: Long): Long = s.toLongOrNull() ?: default
    fun int(s: String, default: Int): Int = s.toIntOrNull() ?: default
    fun weights(line: String): DoubleArray {
        val parts = line.split(',')
        return DoubleArray(TransportAdvisor.FEATURES) { i ->
            parts.getOrNull(i)?.toDoubleOrNull()?.takeIf {
                it.isFinite()
            }?.coerceIn(-TransportAdvisor.CLAMP, TransportAdvisor.CLAMP) ?: 0.0
        }
    }
}
