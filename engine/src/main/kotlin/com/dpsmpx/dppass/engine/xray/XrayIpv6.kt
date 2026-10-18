package com.dpsmpx.dppass.engine.xray

/** Выпускает ли сервер профиля IPv6 (D-66). */
enum class Ipv6Egress {
    /** Ответ по IPv6 через сервер пришёл. */
    FORWARDED,

    /** IPv6 через сервер не прошёл, а IPv4 к тому же оператору тут же прошёл: у сервера нет выхода в IPv6. */
    NOT_FORWARDED,

    /** Не понять: сервер сейчас не отвечает и по IPv4, ядро не запущено, ответ не DNS. */
    UNKNOWN,
}

/** Итог и исходы проб по порядку — для журнала. */
class Ipv6Check(val egress: Ipv6Egress, val outcomes: List<DnsProbeOutcome>)

/**
 * Выход IPv6 через сервер профиля (D-66): запрос DNS по TCP через сервер к
 * адресу IPv6 открытого резолвера — через исходящий proxy, в обход
 * маршрутизации, как проба здоровья (D-32). Ориентиры — Cloudflare и
 * Google, те же операторы, что у проверки сети и замера (D-60…D-62). Они
 * видят адрес сервера, а не телефона, и запрос «. NS» ничего не говорит о
 * пользователе (D-12).
 *
 * «Не выпускает» — только если оба ориентира IPv6 не ответили, а IPv4 к
 * первому ориентиру ([CONTROL]) через тот же сервер тут же ответил. Иначе
 * сбой самого сервера выглядел бы отсутствием IPv6. Маршрут и DNS итог не
 * меняет: это строка на экране, а не настройка (D-05).
 */
object XrayIpv6 {
    val TARGETS: List<String> = listOf("tcp://[2606:4700:4700::1111]:53", "tcp://[2001:4860:4860::8888]:53")

    /** Тот же оператор и протокол, что у первого ориентира, но по IPv4. */
    const val CONTROL: String = "tcp://1.1.1.1:53"

    /** Срок одной пробы: сервер без выхода IPv6 может ждать своего срока соединения, а не отказывать сразу. */
    const val TIMEOUT_MILLIS: Int = 5_000

    /** Отказ пути: соединение закрылось без ответа или данные не пошли. Остальное — не про IPv6. */
    private val REFUSED = setOf(DnsProbeOutcome.UNREACHABLE, DnsProbeOutcome.STALLED)

    /**
     * Пробы по порядку через [ask] (цель → исход): первый ответ IPv6 —
     * «выпускает», не про IPv6 — «не понять» сразу; оба отказа — проба
     * IPv4. Не больше трёх проб.
     */
    fun probe(ask: (String) -> DnsProbeOutcome): Ipv6Check {
        val outcomes = mutableListOf<DnsProbeOutcome>()
        for (target in TARGETS) {
            val o = ask(target).also { outcomes += it }
            if (o == DnsProbeOutcome.OK) return Ipv6Check(Ipv6Egress.FORWARDED, outcomes)
            if (o !in REFUSED) return Ipv6Check(Ipv6Egress.UNKNOWN, outcomes)
        }
        val control = ask(CONTROL).also { outcomes += it }
        return Ipv6Check(if (control == DnsProbeOutcome.OK) Ipv6Egress.NOT_FORWARDED else Ipv6Egress.UNKNOWN, outcomes)
    }
}
