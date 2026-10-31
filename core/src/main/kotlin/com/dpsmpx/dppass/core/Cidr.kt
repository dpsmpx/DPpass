package com.dpsmpx.dppass.core

/**
 * Подсеть: адрес и длина префикса. Хранится канонически — биты хоста
 * обнулены; [parse] сообщает, были ли они ненулевыми (это не меняет
 * смысл подсети, но заслуживает пометки при нормализации).
 */
class Cidr private constructor(val network: IpAddress, val prefix: Int) {
    val isV4: Boolean get() = network.isV4

    operator fun contains(ip: IpAddress): Boolean {
        if (ip.isV4 != network.isV4) return false
        for (i in 0 until prefix) if (ip.bit(i) != network.bit(i)) return false
        return true
    }

    /** Эта подсеть целиком внутри [other]. */
    fun isWithin(other: Cidr): Boolean = other.isV4 == isV4 && other.prefix <= prefix && network in other

    override fun equals(other: Any?): Boolean = other is Cidr && other.prefix == prefix && other.network == network
    override fun hashCode(): Int = network.hashCode() * 31 + prefix
    override fun toString(): String = "$network/$prefix"

    data class Parsed(val cidr: Cidr, val hadHostBits: Boolean)

    companion object {
        val ALL_V4: Cidr = of(IpAddress.parse("0.0.0.0")!!, 0)
        val ALL_V6: Cidr = of(IpAddress.parse("::")!!, 0)

        /**
         * RFC 1918: 10/8, 172.16/12, 192.168/16 — адреса, которые не видны из
         * интернета: раздача туннеля (D-51) и устройство раздачи (D-55).
         */
        val PRIVATE_V4: List<Cidr> = listOf("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16").map { parse(it)!!.cidr }

        fun isPrivateV4(ip: IpAddress): Boolean = PRIVATE_V4.any { ip in it }

        fun of(address: IpAddress, prefix: Int): Cidr {
            require(prefix in 0..address.bitLength) { "длина префикса вне диапазона" }
            return Cidr(mask(address, prefix), prefix)
        }

        fun parse(text: String): Parsed? {
            val slash = text.indexOf('/')
            val ip = IpAddress.parse(if (slash < 0) text else text.substring(0, slash)) ?: return null
            val prefixText = if (slash < 0) null else text.substring(slash + 1)
            if (prefixText != null && (prefixText.isEmpty() || prefixText.length > 3 || !prefixText.all { it.isDigit() })) return null
            val prefix = prefixText?.toInt() ?: ip.bitLength
            if (prefix > ip.bitLength) return null
            val cidr = of(ip, prefix)
            return Parsed(cidr, cidr.network != ip)
        }

        private fun mask(ip: IpAddress, prefix: Int): IpAddress {
            val b = ip.toBytes()
            for (i in b.indices) {
                val bitsHere = (prefix - i * 8).coerceIn(0, 8)
                b[i] = (b[i].toInt() and (0xff shl (8 - bitsHere)) and 0xff).toByte()
            }
            return IpAddress.of(b)
        }

        private fun withBit(ip: IpAddress, index: Int, value: Int): IpAddress {
            val b = ip.toBytes()
            val mask = 1 shl (7 - index % 8)
            b[index / 8] = (if (value == 1) b[index / 8].toInt() or mask else b[index / 8].toInt() and mask.inv()).toByte()
            return IpAddress.of(b)
        }

        /**
         * Дополнение: подсети, которые покрывают [universe] без [excluded].
         *
         * Нужно для Android ниже API 33, где нет `Builder.excludeRoute`:
         * «всё, кроме локальной сети» строится набором маршрутов.
         * Результат минимален для двоичного дерева префиксов.
         */
        fun complement(universe: Cidr, excluded: List<Cidr>): List<Cidr> {
            val relevant = excluded.filter { it.isV4 == universe.isV4 }
            if (relevant.any { universe.isWithin(it) }) return emptyList()
            val inside = relevant.filter { it.isWithin(universe) }
            if (inside.isEmpty()) return listOf(universe)
            val out = mutableListOf<Cidr>()
            fun split(node: Cidr) {
                if (inside.any { node.isWithin(it) }) return
                if (inside.none { it.isWithin(node) }) {
                    out += node
                    return
                }
                val next = node.prefix + 1
                split(of(withBit(node.network, node.prefix, 0), next))
                split(of(withBit(node.network, node.prefix, 1), next))
            }
            split(universe)
            return out
        }
    }
}

/**
 * Адрес интерфейса: адрес узла и длина префикса его сети
 * (`172.19.0.1/30`). В отличие от [Cidr], биты узла не обнуляются: это
 * адрес, который получает интерфейс, а не номер сети.
 */
data class HostAddress(val address: IpAddress, val prefix: Int) {
    init {
        require(prefix in 1..address.bitLength) { "длина префикса вне диапазона" }
    }

    override fun toString(): String = "$address/$prefix"

    companion object {
        /** `адрес/префикс` → адрес интерфейса; не разобрать — null. */
        fun parse(text: String): HostAddress? {
            val slash = text.indexOf('/')
            if (slash < 0) return null
            val ip = IpAddress.parse(text.substring(0, slash)) ?: return null
            val prefix = text.substring(slash + 1).toIntOrNull() ?: return null
            return if (prefix in 1..ip.bitLength) HostAddress(ip, prefix) else null
        }
    }
}
