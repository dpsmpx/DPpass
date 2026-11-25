package com.dpsmpx.dppass.app

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.Job
import kotlinx.coroutines.launch

/**
 * Single diagnostic slot, confined to the owning UI dispatcher.
 * Cancelling a job does not release the slot: a blocking JNI call may
 * still be executing. Completion is marshalled back to the same scope.
 */
internal class DptsDiagnosticJob(
    private val scope: CoroutineScope,
    private val changed: () -> Unit,
) {
    private var current: Job? = null
    val busy: Boolean get() = current != null
    val cancellable: Boolean get() = current?.isActive == true

    fun start(block: suspend CoroutineScope.() -> Unit): Boolean {
        if (busy) return false
        val launched = scope.launch(start = CoroutineStart.LAZY, block = block)
        current = launched
        launched.invokeOnCompletion {
            scope.launch {
                if (current === launched) {
                    current = null
                    changed()
                }
            }
        }
        launched.start()
        changed()
        return true
    }

    fun cancel() {
        current?.cancel()
        changed()
    }
}
