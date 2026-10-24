package com.dpsmpx.dppass.desktop

import com.dpsmpx.dppass.diagnostics.Logger
import com.dpsmpx.dppass.engine.ShareSpec

/**
 * Раздача под туннелем (D-84, как у сервиса туннеля Android, D-51): раз в
 * [POLL_MILLIS] — адреса точки доступа ПК ([LinuxShareInterfaces]). Набор
 * сменился (точку доступа включили, выключили, сменился адрес) — пора
 * переподключаться: конфигурация ядра во время работы не меняется, новые
 * входы — только новым запуском.
 */
class ShareWatch(
    private val log: Logger,
    /** На чём раздаёт туннель; раздача включена, а точки доступа не было — пусто. */
    private val current: List<ShareSpec.Endpoint>,
    private val find: () -> List<ShareSpec.Endpoint>,
) {
    /** До смены набора — тогда возврат: переподключиться; или до отмены (остановка сеанса). */
    suspend fun run(sleep: suspend (Long) -> Unit) {
        var previous: List<ShareSpec.Endpoint>? = null
        while (true) {
            sleep(POLL_MILLIS)
            val wanted = find()
            if (shouldReconnect(current, wanted, previous)) {
                log.info("share_interfaces_changed", "was" to current.size, "now" to wanted.size)
                return
            }
            previous = wanted
        }
    }

    companion object {
        /** Как на Android: включённую точку доступа DPpass замечает за несколько секунд. */
        const val POLL_MILLIS: Long = 5_000

        /**
         * Переподключаться ли: туннель раздаёт на [current], опрос дал [wanted],
         * прошлый — [previous]. Набор другой и держится два опроса подряд: при
         * включении точки доступа адрес появляется не сразу, и без этого вышло
         * бы два переподключения вместо одного. NetworkManager сам говорит, что
         * раздаёт, — второй снимок не защита от чужой сети, как на Android, а
         * только от лишнего переподключения.
         */
        fun shouldReconnect(current: List<ShareSpec.Endpoint>, wanted: List<ShareSpec.Endpoint>, previous: List<ShareSpec.Endpoint>?): Boolean =
            wanted.toSet() != current.toSet() && wanted.toSet() == previous?.toSet()
    }
}
