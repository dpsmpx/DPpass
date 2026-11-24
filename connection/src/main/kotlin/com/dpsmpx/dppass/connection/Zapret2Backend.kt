package com.dpsmpx.dppass.connection

/** Separate, local, opt-in transport. Unknown persisted values fail closed. */
enum class Zapret2Backend(val wire: String) {
    OFF("off"), ROOT("root"), VPN_SERVICE("vpnservice"),
    BYEDPI_ROOT("byedpi-root"), BYEDPI_VPN("byedpi-vpn");

    val rooted: Boolean get() = this == ROOT || this == BYEDPI_ROOT
    val vpn: Boolean get() = this == VPN_SERVICE || this == BYEDPI_VPN
    val byedpi: Boolean get() = this == BYEDPI_ROOT || this == BYEDPI_VPN
    companion object {
        fun of(value: String?): Zapret2Backend = entries.firstOrNull { it.wire == value } ?: OFF
    }
}
