package com.dpsmpx.dppass.app

import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.withContext

internal interface RootDpiRuntime {
    suspend fun start(): Result<Unit>
    suspend fun stop(): Result<Unit>
    suspend fun alive(): Boolean
}

/** A successful privileged start must be owned by the service or rolled
 * back before cancellation can escape. Null means the owner declined.
 */
internal suspend fun RootDpiRuntime.startAndAccept(
    accept: suspend () -> Boolean,
    onRollbackFailure: (Throwable) -> Unit,
): Result<Unit>? = withContext(NonCancellable) {
    val result = start()
    if (result.isFailure) return@withContext result
    var accepted = false
    try {
        accepted = accept()
        if (accepted) result else null
    } finally {
        if (!accepted) runCatching { stop().getOrThrow() }.onFailure(onRollbackFailure)
    }
}

/** Preserve the startup error, but make failed compensating cleanup visible.
 * Initial cleanup is deliberately outside this transaction: if it fails, do
 * not attempt to launch another daemon.
 */
internal fun rootLaunchWithRollback(launch: () -> Unit, rollback: () -> Unit) {
    try {
        launch()
    } catch (startup: Exception) {
        try {
            rollback()
        } catch (cleanup: Exception) {
            val failure = IllegalStateException(
                (startup.message ?: "ROOT startup failed") + "; ROOT cleanup failed",
                startup,
            )
            failure.addSuppressed(cleanup)
            throw failure
        }
        throw startup
    }
}

/** Stop may fail by returning Result.failure or by throwing. Keep both
 * paths observable and finish the cleanup attempt even during cancellation.
 */
internal suspend fun RootDpiRuntime.stopForCleanup(): Result<Unit> =
    withContext(NonCancellable) {
        try {
            stop()
        } catch (error: Exception) {
            Result.failure(error)
        }
    }
