package com.dpsmpx.dppass.app

import com.dpsmpx.dppass.connection.AttemptRecord
import com.dpsmpx.dppass.connection.Exclusion
import com.dpsmpx.dppass.core.ProfileId
import com.dpsmpx.dppass.diagnostics.Diagnostic
import com.dpsmpx.dppass.engine.ShareSpec
import com.dpsmpx.dppass.engine.TrafficStats
import com.dpsmpx.dppass.engine.xray.Ipv6Egress
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

/**
 * Состояние туннеля для интерфейса (D-34). Меняет его только сервис
 * туннеля; экраны, плитка и уведомление его показывают. Без Android:
 * переходы проверяются на хосте.
 */
sealed interface TunnelStatus {
    /** Туннеля нет и не было отказа с прошлого запуска. */
    data object Idle : TunnelStatus

    /** Идёт подключение; [profileName] — кого проверяет сейчас (null — план ещё составляется). */
    data class Connecting(val profileName: String?) : TunnelStatus

    /** [sinceMillis] — время суток подключения (для уведомления); [sinceMonotonic] — для длительности. */
    data class Connected(val profileId: ProfileId, val profileName: String, val sinceMillis: Long, val sinceMonotonic: Long = 0) : TunnelStatus

    data object Stopping : TunnelStatus

    /** Последняя попытка не удалась; причина — с кодом (D-22), туннеля нет. */
    data class Failed(val reason: Diagnostic) : TunnelStatus

    /** Туннель есть или поднимается: кнопка экрана — «Отключить», выбор сервера — переподключение. */
    val busy: Boolean get() = this is Connecting || this is Connected
}

/** Трафик сессии (D-40): итоги с подключения и скорость по счётчикам ядра. */
data class Traffic(val upBytes: Long, val downBytes: Long, val upPerSec: Long, val downPerSec: Long) {
    companion object {
        val ZERO: Traffic = Traffic(0, 0, 0, 0)
    }
}

/**
 * Скорость по накопленным счётчикам ядра (`EngineSession.stats`, D-25):
 * разница за прошедшее время. Счётчики уменьшились — это новая сессия,
 * отсчёт заново, а не «отрицательная скорость». Время — монотонное.
 */
class TrafficMeter {
    private var lastAt: Long? = null
    private var last: TrafficStats? = null

    fun sample(stats: TrafficStats, nowMillis: Long): Traffic {
        val prev = last
        val prevAt = lastAt
        last = stats
        lastAt = nowMillis
        if (prev == null || prevAt == null || nowMillis <= prevAt || stats.uplinkBytes < prev.uplinkBytes || stats.downlinkBytes < prev.downlinkBytes) {
            return Traffic(stats.uplinkBytes, stats.downlinkBytes, 0, 0)
        }
        val dt = nowMillis - prevAt
        return Traffic(
            stats.uplinkBytes,
            stats.downlinkBytes,
            (stats.uplinkBytes - prev.uplinkBytes) * 1000 / dt,
            (stats.downlinkBytes - prev.downlinkBytes) * 1000 / dt,
        )
    }

    fun reset() {
        last = null
        lastAt = null
    }
}

/**
 * Когда обновлять уведомление туннеля (D-40, `PERFORMANCE_BUDGET.md`):
 * счётчики — раз в [TICK_MILLIS], пока экран включён; уведомление — каждый
 * [NOTIFY_EVERY]-й раз: каждое обновление стоит батареи. Экран выключен —
 * ни того, ни другого, и счёт стоит.
 */
class NotificationPace {
    private var count = 0

    /** Прошёл [TICK_MILLIS]; true — обновить уведомление. */
    fun tick(interactive: Boolean): Boolean = interactive && count++ % NOTIFY_EVERY == 0

    companion object {
        const val TICK_MILLIS: Long = 1_000

        /** Уведомление — раз в 2 с. */
        const val NOTIFY_EVERY: Int = 2
    }
}

/**
 * Вопрос о сбое выбранного сервера (D-58): «[fromName]» перестал отвечать
 * по [reason] — перейти ли на «[toName]». Пока туннель поднят и ответа нет.
 */
data class ServerOffer(val fromId: ProfileId, val fromName: String, val toId: ProfileId, val toName: String, val reason: Diagnostic)

/**
 * Последнее подключение (D-15): попытки по порядку с причинами и исходами
 * и исключённые с причинами — то, что сервис туннеля сохранил после плана,
 * для экрана «Почему этот сервер». Без сессии и без секретов.
 */
data class PlanSnapshot(
    val atMillis: Long,
    val attempts: List<AttemptRecord>,
    val excluded: List<Exclusion>,
    /** Подключение через устройство раздачи (D-55): план из одного кандидата. */
    val viaRelay: Boolean,
)

/** Итог пробы IPv6 через сервер [profileId] сессии (D-66): только в памяти, только для экрана. */
data class Ipv6Note(val profileId: ProfileId, val egress: Ipv6Egress, val atMillis: Long)

/** Одно состояние на процесс: сервис и экраны живут в одном процессе (D-30). */
object TunnelState {
    private val flow = MutableStateFlow<TunnelStatus>(TunnelStatus.Idle)
    private val trafficFlow = MutableStateFlow(Traffic.ZERO)
    private val shareFlow = MutableStateFlow<List<ShareSpec.Endpoint>>(emptyList())
    private val shareRefusedFlow = MutableStateFlow(false)
    private val offerFlow = MutableStateFlow<ServerOffer?>(null)
    private val planFlow = MutableStateFlow<PlanSnapshot?>(null)
    private val ipv6Flow = MutableStateFlow<Ipv6Note?>(null)

    val status: StateFlow<TunnelStatus> = flow.asStateFlow()

    /** Трафик текущей сессии; без туннеля — нули. */
    val traffic: StateFlow<Traffic> = trafficFlow.asStateFlow()

    /** На каких адресах сейчас раздаётся туннель (D-51); без туннеля или раздачи — пусто. */
    val share: StateFlow<List<ShareSpec.Endpoint>> = shareFlow.asStateFlow()

    /** Раздача просилась, но ядро с её входами не запустилось (адрес пропал, порт занят): туннель — без неё. */
    val shareRefused: StateFlow<Boolean> = shareRefusedFlow.asStateFlow()

    /** Вопрос о сбое выбранного сервера (D-58); без туннеля или после ответа — null. */
    val offer: StateFlow<ServerOffer?> = offerFlow.asStateFlow()

    fun set(next: TunnelStatus) {
        flow.value = next
        if (!next.busy) {
            trafficFlow.value = Traffic.ZERO
            shareFlow.value = emptyList()
            shareRefusedFlow.value = false
            offerFlow.value = null
            ipv6Flow.value = null
        }
    }

    /** Выпускает ли сервер сессии IPv6 (D-66); без туннеля, до пробы и после смены сервера — null. */
    val ipv6: StateFlow<Ipv6Note?> = ipv6Flow.asStateFlow()

    fun ipv6(next: Ipv6Note?) {
        ipv6Flow.value = next
    }

    fun offer(next: ServerOffer?) {
        offerFlow.value = next
    }

    /** Последнее подключение (D-15); остаётся и после остановки — объяснить отказ. */
    val plan: StateFlow<PlanSnapshot?> = planFlow.asStateFlow()

    fun plan(next: PlanSnapshot) {
        planFlow.value = next
    }

    fun traffic(next: Traffic) {
        trafficFlow.value = next
    }

    fun share(next: List<ShareSpec.Endpoint>, refused: Boolean = false) {
        shareFlow.value = next
        shareRefusedFlow.value = refused
    }
}
