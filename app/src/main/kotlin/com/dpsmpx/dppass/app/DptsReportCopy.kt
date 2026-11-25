package com.dpsmpx.dppass.app

/** Clipboard failures never invalidate an already completed diagnostic. */
internal object DptsReportCopy {
    fun attempt(write: () -> Boolean): Boolean = try {
        write()
    } catch (_: SecurityException) {
        false
    } catch (_: IllegalStateException) {
        false
    }
}
