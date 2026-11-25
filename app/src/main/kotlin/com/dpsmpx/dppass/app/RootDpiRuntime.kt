package com.dpsmpx.dppass.app

import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
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
    onRollbackFailure: suspend (Throwable) -> Unit,
): Result<Unit>? = withContext(NonCancellable) {
    val result = start()
    if (result.isFailure) {
        val error = result.exceptionOrNull()
        if (error is RootCleanupRequired) onRollbackFailure(error)
        return@withContext result
    }
    var accepted = false
    try {
        accepted = accept()
        if (accepted) result else null
    } finally {
        if (!accepted) {
            val failure = runCatching { stop().getOrThrow() }.exceptionOrNull()
            if (failure != null) onRollbackFailure(failure)
        }
    }
}

/** A failed startup that still needs a cleanup owner. */
internal sealed class RootCleanupRequired(message: String, cause: Exception) :
    IllegalStateException(message, cause)

internal class RootInitialCleanupFailure(cleanup: Exception) :
    RootCleanupRequired("ROOT initial cleanup failed", cleanup)

/** Startup failed and compensating cleanup could not be confirmed. */
internal class RootStartupCleanupFailure(startup: Exception, cleanup: Exception) :
    RootCleanupRequired((startup.message ?: "ROOT startup failed") + "; ROOT cleanup failed", startup) {
    init { addSuppressed(cleanup) }
}

/** Initial cleanup precedes any launch. Keep its failure retryable. */
internal fun rootPrepareCleanup(cleanup: () -> Unit) {
    try {
        cleanup()
    } catch (error: Exception) {
        throw RootInitialCleanupFailure(error)
    }
}

/** Preserve the startup error, but make failed compensating cleanup visible.
 * Initial cleanup remains a separate prerequisite.
 */
internal fun rootLaunchWithRollback(launch: () -> Unit, rollback: () -> Unit) {
    try {
        launch()
    } catch (startup: Exception) {
        try {
            rollback()
        } catch (cleanup: Exception) {
            throw RootStartupCleanupFailure(startup, cleanup)
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

/** Process-wide ownership for the legacy ROOT resources. A fresh service
 * instance must not start while another instance owns (or is cleaning) them.
 * An obsolete handle must never stop a newer owner. This does not lock
 * external watchdog scripts or survive process death.
 */
internal interface RootRuntimeHandle : RootDpiRuntime {
    /** Only call after the owning service has finished its destruction cleanup. */
    suspend fun abandon()
}

internal class RootRuntimeCoordinator {
    private val mutex = Mutex()
    private data class Owner(val token: Any, val delegate: RootDpiRuntime, var abandoned: Boolean = false)
    private var owner: Owner? = null

    /** Retry only an explicitly abandoned owner, never a live service's resources. */
    suspend fun retryAbandonedCleanup(): Result<Unit> = recoverAbandoned(requireIdle = false)

    /** Before any new connection (including non-ROOT), require no remaining
     * process-local ROOT owner. An active owner must not be stopped here.
     */
    suspend fun prepareForConnection(): Result<Unit> = recoverAbandoned(requireIdle = true)

    private suspend fun recoverAbandoned(requireIdle: Boolean): Result<Unit> = withContext(NonCancellable) {
        mutex.withLock {
            val current = owner ?: return@withLock Result.success(Unit)
            if (!current.abandoned) {
                return@withLock if (requireIdle) Result.failure(
                    IllegalStateException("ROOT: another service still owns the resources"),
                ) else Result.success(Unit)
            }
            val result = current.delegate.stopForCleanup()
            if (result.isSuccess) owner = null
            result
        }
    }

    fun bind(delegate: RootDpiRuntime): RootRuntimeHandle = object : RootRuntimeHandle {
        private val token = Any()

        override suspend fun start(): Result<Unit> = mutex.withLock {
            if (owner != null) {
                return@withLock Result.failure(IllegalStateException("ROOT: previous owner has not completed cleanup"))
            }
            val result = delegate.start()
            if (result.isSuccess || result.exceptionOrNull() is RootCleanupRequired) {
                owner = Owner(token, delegate)
            }
            result
        }

        override suspend fun stop(): Result<Unit> = mutex.withLock {
            // No owned resources remain for this handle.
            if (owner?.token !== token) return@withLock Result.success(Unit)
            val result = delegate.stopForCleanup()
            if (result.isSuccess) owner = null
            result
        }

        override suspend fun alive(): Boolean = mutex.withLock {
            owner?.token === token && owner?.abandoned == false && delegate.alive()
        }

        override suspend fun abandon() = withContext(NonCancellable) {
            mutex.withLock {
                val current = owner
                if (current?.token === token) current.abandoned = true
            }
        }
    }
}

internal val processRootRuntimeCoordinator = RootRuntimeCoordinator()
