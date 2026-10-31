package com.dpsmpx.dppass.desktop

import com.dpsmpx.dppass.core.IpAddress
import com.dpsmpx.dppass.engine.ShareSpec

/**
 * Интерфейсы раздачи ПК на Windows (D-101, к D-84): только частная сторона
 * общего доступа к подключению к интернету (ICS) — «Мобильный хот-спот» и
 * ICS у адаптера. Что раздаёт — говорит сама ICS через мост
 * ([WindowsNative.nativeSharedInterfaces], `tools/xray/bridge/share_windows.go`),
 * а не признаки адаптера: адаптер Wi-Fi Direct бывает и клиентом чужой
 * группы, второй провод выглядит так же, как раздача.
 *
 * Ошибка в сторону «не раздавать»: ICS не ответила или ответ не разобран —
 * адресов нет. Сеть «вверх по течению» и адаптер DPpass мост исключает сам.
 */
class WindowsShareInterfaces(
    /** Ответ моста: статус первым байтом, затем адреса с длиной префикса по строке. */
    private val shared: () -> ByteArray,
) : DesktopShares {
    override fun find(): ShareScan {
        val reply = shared()
        if (reply.isEmpty() || reply[0].toInt() != 0) {
            val text = if (reply.isEmpty()) "" else String(reply, 1, reply.size - 1, Charsets.UTF_8)
            val code = HRESULT.find(text)?.value?.let { " hr=$it" }.orEmpty()
            return ShareScan(emptyList(), FAILED, "ics=failed kind=${reply.firstOrNull()?.toInt() ?: -1}$code")
        }
        val lines = String(reply, 1, reply.size - 1, Charsets.UTF_8).lines().filter { it.isNotBlank() }
        val addresses = parse(lines) ?: return ShareScan(emptyList(), UNPARSED, "ics=unparsed")
        val endpoints = addresses
            .mapNotNull { (ip, prefix) -> ShareSpec.Endpoint.ofOrNull(ip, prefix) }
            .distinctBy { it.address }
            .sortedBy { it.address.toString() }
        return ShareScan(endpoints, if (endpoints.isEmpty()) NO_HOTSPOT else "", "ics=0 shared=${lines.size} endpoints=${endpoints.size}")
    }

    override val condition: String =
        "Только пока DPpass подключён и в Windows включён «Мобильный хот-спот» или общий доступ к подключению к интернету (ICS)"

    override val firewall: String =
        "• Брандмауэр Windows может спросить, разрешить ли DPpass входящие подключения, — разрешите для сети точки доступа, " +
            "иначе другое устройство не подключится. Если раньше отказали — разрешите dppass.exe в «Брандмауэре Защитника " +
            "Windows» («Разрешение взаимодействия с приложением»)."

    companion object {
        /** Код отказа COM из текста моста — в журнал вместо текста: в нём нет ни имён, ни адресов (D-57). */
        private val HRESULT = Regex("0x[0-9a-f]{8}")

        const val NO_HOTSPOT: String =
            "Нет точки доступа. Включите «Мобильный хот-спот» в параметрах Windows («Сеть и Интернет») или общий доступ к " +
                "подключению к интернету (ICS) у адаптера — DPpass заметит это за несколько секунд и переподключится. Другие " +
                "сети ПК для раздачи не годятся: вход прокси встал бы в чужую сеть."

        const val FAILED: String =
            "Windows не ответила, что раздаёт ПК (общий доступ к подключению, ICS), — раздачи нет: лучше не раздавать, " +
                "чем открыть вход не в той сети."

        const val UNPARSED: String = "Ответ Windows о раздаче не разобран — раздачи нет: лучше не раздавать, чем открыть вход не в той сети."

        /** Строки «IPv4/длина префикса»; любая другая строка — null: весь ответ не разобран. */
        fun parse(lines: List<String>): List<Pair<IpAddress, Int>>? = lines.map { line ->
            val slash = line.indexOf('/')
            if (slash < 0) return null
            val ip = IpAddress.parseV4(line.substring(0, slash)) ?: return null
            val prefix = line.substring(slash + 1).toIntOrNull()?.takeIf { it in 1..IPV4_BITS } ?: return null
            ip to prefix
        }

        private const val IPV4_BITS = 32
    }
}
