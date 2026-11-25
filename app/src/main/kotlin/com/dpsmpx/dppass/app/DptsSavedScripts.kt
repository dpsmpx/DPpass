package com.dpsmpx.dppass.app

import com.dpsmpx.dppass.engine.xray.DptsScript

/** Consistent admission for editable drafts, including preference restoration. */
internal object DptsSavedScripts {
    const val MAX_NAME_LENGTH = 80
    const val MAX_SCRIPTS = 30
    private const val PREFIX = "script."

    fun validDraft(name: String, source: String): Boolean =
        name.length in 1..MAX_NAME_LENGTH &&
            name == name.trim() && name.isNotBlank() &&
            name.none { it.category in setOf(
                CharCategory.CONTROL, CharCategory.FORMAT,
                CharCategory.LINE_SEPARATOR, CharCategory.PARAGRAPH_SEPARATOR) } &&
            source.isNotBlank() && source.length <= DptsScript.MAX_SOURCE_LENGTH

    // Ignore malformed preference values. The stable order makes the limit
    // independent of SharedPreferences iteration order. Do not delete drafts.
    fun restore(values: Map<String, *>): MutableMap<String, String> {
        val drafts = linkedMapOf<String, String>()
        for (key in values.keys.sorted()) {
            if (drafts.size >= MAX_SCRIPTS) break
            if (!key.startsWith(PREFIX)) continue
            val source = values[key] as? String ?: continue
            val name = key.removePrefix(PREFIX)
            if (validDraft(name, source)) drafts[name] = source
        }
        return drafts
    }
}
