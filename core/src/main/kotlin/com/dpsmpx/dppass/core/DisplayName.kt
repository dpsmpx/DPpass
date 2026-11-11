package com.dpsmpx.dppass.core

/** Опасные невидимые и направляющие знаки в подписи; ZWJ/ZWNJ для emoji и языков допустимы. */
object DisplayName {
    fun safe(value: String): Boolean = value.none {
        it.isISOControl() || it in '\u202a'..'\u202e' || it in '\u2066'..'\u2069' ||
            it == '\u200b' || it == '\u2060' || it == '\ufeff'
    }
}
