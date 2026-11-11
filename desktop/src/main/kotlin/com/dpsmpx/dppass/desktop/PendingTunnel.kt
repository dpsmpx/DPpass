package com.dpsmpx.dppass.desktop

import com.dpsmpx.dppass.diagnostics.Outcome
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.withContext

/** TUN до передачи сеансу: отмена возврата из IO не теряет уже созданный ресурс (аудит R-01). */
internal class PendingTunnel {
    private var pending: DesktopTunnel? = null

    suspend fun acquire(open: () -> Outcome<DesktopTunnel>): Outcome<DesktopTunnel> =
        withContext(NonCancellable + Dispatchers.IO) {
            check(pending == null) { "предыдущий TUN ещё не передан сеансу" }
            // Ссылка сохраняется внутри IO: его результат withContext может отбросить при отмене вызывающего.
            open().also { if (it is Outcome.Success) pending = it.value }
        }

    fun take(): DesktopTunnel? = pending.also { pending = null }

    suspend fun closeUnclaimed() {
        withContext(NonCancellable + Dispatchers.IO) {
            val handle = pending
            pending = null
            handle?.close()
        }
    }
}
