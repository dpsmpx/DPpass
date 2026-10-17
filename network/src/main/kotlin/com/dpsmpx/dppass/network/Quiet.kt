package com.dpsmpx.dppass.network

import com.dpsmpx.dppass.core.Clock

/**
 * Свои замеры по кнопке — замер скорости через туннель (D-61) и проверка
 * сети (D-60) — и [afterMillis] после них: проба наблюдателя сессии (D-44)
 * в это время мерит сам замер, а не сервер, и в модель устойчивости не идёт
 * (T14). 17 октября 2026 все три провала пробы сразу после замера скорости
 * пришлись на проверку сети, шедшую следом; между замерами пробы проходили.
 *
 * Замеров может идти несколько сразу: окно — пока идёт хоть один и
 * [afterMillis] после последнего. Время — монотонное и снаружи (D-21);
 * доступ под замком: начинают и заканчивают экраны, читает сервис.
 */
class QuietWindow(private val clock: Clock, private val afterMillis: Long) {
    private var running = 0
    private var endedAt: Long? = null

    init {
        require(afterMillis >= 0)
    }

    /** Замер начался. Каждому [begin] — свой [end], и прерванному тоже. */
    @Synchronized
    fun begin() {
        running++
    }

    @Synchronized
    fun end() {
        check(running > 0) { "конец замера без начала" }
        running--
        endedAt = clock.nowMillis()
    }

    /**
     * Проба сейчас мерила бы замер: он идёт или кончился меньше
     * [afterMillis] назад. Проверять до пробы (не начинать) и после (не
     * учитывать: замер мог начаться, пока она шла).
     */
    @Synchronized
    fun active(): Boolean = running > 0 || endedAt?.let { clock.nowMillis() - it < afterMillis } == true
}
