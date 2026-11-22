package com.dpsmpx.dppass.app.alpine

/**
 * Selection is based on APK contents, not connection success.
 * An Alpine-enabled APK must never silently use the in-process planner
 * just because its native PRoot executables are missing or unusable.
 */
internal enum class AlpinePlannerSelection {
    IN_PROCESS,
    ALPINE,
    UNAVAILABLE;

    companion object {
        fun choose(bundled: Boolean, supported: Boolean): AlpinePlannerSelection =
            when {
                !bundled -> IN_PROCESS
                supported -> ALPINE
                else -> UNAVAILABLE
            }
    }
}
