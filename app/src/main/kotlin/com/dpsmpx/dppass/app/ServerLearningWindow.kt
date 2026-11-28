package com.dpsmpx.dppass.app

/** One active connection's transient, pre-outcome evidence. No Android dependency. */
internal class ServerLearningWindow<P : Any, T : Any> {
    private val guard = Any()
    private var current: Any? = null
    private var pending: Pair<P, T>? = null
    private var consumed = false

    fun begin(): Any = synchronized(guard) {
        clear()
        Any().also { current = it }
    }

    fun publish(token: Any, plan: P, batch: T): Boolean = synchronized(guard) {
        if (current !== token || pending != null || consumed) return@synchronized false
        pending = plan to batch
        true
    }

    fun take(token: Any, plan: P): T? = synchronized(guard) {
        if (current !== token || consumed) return@synchronized null
        val entry = pending
        if (entry == null || entry.first !== plan) {
            clear()
            return@synchronized null
        }
        pending = null
        consumed = true
        entry.second
    }

    // Linearize persistence with handoff/reset, after the caller's
    // independent model-byte comparison.
    fun commitIfCurrent(token: Any, persist: () -> Boolean): Boolean = synchronized(guard) {
        if (current !== token || !consumed) return@synchronized false
        try {
            persist()
        } finally {
            clear()
        }
    }

    fun finish(token: Any) = synchronized(guard) {
        if (current === token) clear()
    }

    fun reset() = synchronized(guard) { clear() }

    private fun clear() {
        current = null
        pending = null
        consumed = false
    }
}
