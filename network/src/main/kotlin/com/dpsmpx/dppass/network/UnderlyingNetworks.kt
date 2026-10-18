package com.dpsmpx.dppass.network

/**
 * Какая из сетей устройства — сеть под туннелем (D-40, D-67): её меряет
 * проверка сети, её смена — повод проверить новую, её тип и тарификацию
 * видят система и приложения (`setUnderlyingNetworks`).
 *
 * Не колбэк «сети по умолчанию»: 18 октября 2026 на телефоне автора он за
 * сессию ни разу не сообщил о переходе Wi-Fi ↔ мобильная — только сеть при
 * регистрации (во всех 17 присланных журналах так). Сервис слушает все сети
 * без VPN и при каждом их событии выбирает нынешнюю здесь.
 *
 * Чистая логика: сети — снимки того, что сообщает система, ключ —
 * непрозрачный (`Network.getNetworkHandle()`), в журнал не идёт.
 */
object UnderlyingNetworks {
    /** Сеть устройства, как её видит система сейчас. */
    data class Candidate(
        val handle: Long,
        val type: NetworkType,
        val vpn: Boolean,
        val internet: Boolean,
        /** Система проверила доступ в интернет (`NET_CAPABILITY_VALIDATED`). */
        val validated: Boolean,
    )

    /**
     * Сеть под туннелем: сеть по умолчанию процесса ([active]), если она не
     * VPN и с доступом в интернет, — процесс DPpass вне своего туннеля
     * (D-17). Иначе — лучшая из [all] без VPN: проверенная системой раньше
     * непроверенной, Wi-Fi и Ethernet раньше мобильной (так их ранжирует и
     * система), при равенстве — по порядку списка. null — такой сети нет.
     */
    fun pick(active: Candidate?, all: List<Candidate>): Candidate? {
        if (active != null && usable(active)) return active
        return all.filter(::usable).sortedWith(compareBy({ !it.validated }, { rank(it.type) })).firstOrNull()
    }

    private fun usable(c: Candidate): Boolean = !c.vpn && c.internet

    private fun rank(type: NetworkType): Int = when (type) {
        NetworkType.WIFI, NetworkType.ETHERNET -> 0
        NetworkType.MOBILE -> 1
        NetworkType.OTHER, NetworkType.NONE -> 2
    }
}
