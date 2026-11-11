package com.dpsmpx.dppass.tunnel

/** Владелец fd с момента establish: старый TUN закрывается только после появления нового. */
class TunnelOwner {
    @Volatile
    private var handle: TunnelHandle? = null

    val present: Boolean get() = handle != null

    @Synchronized
    fun replace(next: TunnelHandle?) {
        val previous = handle
        handle = next
        if (previous !== next) previous?.close()
    }

    fun close() = replace(null)
}
