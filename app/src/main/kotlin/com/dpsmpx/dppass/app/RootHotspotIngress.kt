package com.dpsmpx.dppass.app

/** D-120: классификация одного пакета с приватного входа шлюза, не маршрутизация. */
internal object RootHotspotIngress {
    enum class Action { DROP, TCP, DNS }

    // Принимаем только уже отделённые ядром пакеты L3 с точной длиной.
    // Опции IPv4, фрагменты, IPv6 и остальной UDP не входят в первый этап.
    fun classify(packet: ByteArray, size: Int): Action {
        if (size !in 20..minOf(packet.size, 65_535)) return Action.DROP
        fun octet(i: Int) = packet[i].toInt() and 0xff
        fun word(i: Int) = (octet(i) shl 8) or octet(i + 1)
        if (octet(0) != 0x45 || word(2) != size || word(6) and 0xbfff != 0) return Action.DROP
        return when (octet(9)) {
            6 -> {
                if (size < 40) return Action.DROP
                val tcpHeader = (octet(32) ushr 4) * 4
                if (tcpHeader !in 20..(size - 20) || word(20) == 0 || word(22) == 0) return Action.DROP
                if (word(22) == 53) Action.DNS else Action.TCP
            }
            17 -> if (size >= 40 && word(20) != 0 && word(22) == 53 && word(24) == size - 20) {
                Action.DNS
            } else {
                Action.DROP
            }
            else -> Action.DROP
        }
    }
}
