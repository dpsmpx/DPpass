package com.dpsmpx.dppass.connection

import com.dpsmpx.dppass.core.Clock
import com.dpsmpx.dppass.network.NetworkAssessment
import com.dpsmpx.dppass.network.RestrictionClass

/**
 * Память о режиме сети (D-64): итог последней проверки сети (D-60) в той же
 * сети, пока он свежий. В план идёт только белый список — класс, сверенный
 * на телефоне (D-62), — и только мягко: порядок, а не исключения.
 *
 * Белые списки включают и выключают без предупреждения; когда их нет,
 * обычно действуют чёрные (автор, 17.10.2026), и туннель нужен всё равно.
 * Поэтому память живёт [ttlMillis] — и до смены сети, до новой проверки или
 * до опровержения: подключился сервер, который под белым списком только
 * отказывал ([DPpassCore.failingUnder]).
 *
 * Только в памяти процесса: ни итога, ни сети на диске и в журнале (D-12).
 * Сеть — непрозрачный ключ (на Android — `Network.getNetworkHandle()`).
 * Время — монотонное и снаружи (D-21).
 */
class RegimeMemory(private val clock: Clock, private val ttlMillis: Long = TTL_MILLIS) {
    private class Entry(val assessment: NetworkAssessment, val network: Long, val atMillis: Long)

    private var last: Entry? = null

    init {
        require(ttlMillis > 0)
    }

    /** Итог проверки в сети [network] — любой: «не белый список» тоже сведение. */
    @Synchronized
    fun remember(assessment: NetworkAssessment, network: Long) {
        last = Entry(assessment, network, clock.nowMillis())
    }

    /** Белый список по свежей проверке в сети [network]; null — режим неизвестен. */
    @Synchronized
    fun allowlist(network: Long?): NetworkAssessment? {
        val e = last ?: return null
        if (network == null || e.network != network || clock.nowMillis() - e.atMillis >= ttlMillis) return null
        return e.assessment.takeIf { it.restriction == RestrictionClass.ALLOWLIST_LIKE }
    }

    /** Сколько мс назад была проверка; null — её не было или память забыта. */
    @Synchronized
    fun ageMillis(): Long? = last?.let { clock.nowMillis() - it.atMillis }

    /** Опровергнута или больше не нужна: режим снова неизвестен. */
    @Synchronized
    fun forget() {
        last = null
    }

    companion object {
        /**
         * 30 минут — ориентир, а не замер: сколько держится белый список,
         * неизвестно; дольше — выше риск вести себя по выключенному списку,
         * короче — чаще проверять. Сверка — на телефоне (`TODO.md`).
         */
        const val TTL_MILLIS: Long = 30L * 60 * 1000
    }
}
