package com.dpsmpx.dppass.connection

/** Separate, local, opt-in transport. Unknown persisted values fail closed. */
enum class Zapret2Backend(val wire: String) {
    OFF("off"), ROOT("root"), VPN_SERVICE("vpnservice");
    companion object {
        fun of(value: String?): Zapret2Backend = entries.firstOrNull { it.wire == value } ?: OFF
    }
}
