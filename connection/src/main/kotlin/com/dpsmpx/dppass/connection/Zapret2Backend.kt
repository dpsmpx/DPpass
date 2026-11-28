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

        /** An active local choice wins. Missing, unknown or OFF history
         * selects the unprivileged default, never ROOT. */
        fun preferredLocal(active: Zapret2Backend, remembered: String?): Zapret2Backend =
            active.takeUnless { it == OFF }
                ?: of(remembered).takeUnless { it == OFF }
                ?: VPN_SERVICE

        /** Returning to a remembered privileged executor is still an
         * explicit ROOT transition, never an implicit fallback. */
        fun requiresRootConfirmation(current: Zapret2Backend, requested: Zapret2Backend): Boolean =
            requested.rooted && requested != current
    }
}
