package com.dpsmpx.dppass.app

import com.dpsmpx.dppass.engine.xray.DptsScript

/** Consistent admission for editable drafts, including preference restoration. */
internal object DptsSavedScripts {
    const val MAX_NAME_LENGTH = 80
    const val MAX_SCRIPTS = 30
    private const val PREFIX = "script."
    private val forbiddenNameCategories = setOf(
        CharCategory.CONTROL, CharCategory.FORMAT,
        CharCategory.LINE_SEPARATOR, CharCategory.PARAGRAPH_SEPARATOR)

    data class ScriptId(val name: String, val personal: Boolean)
    data class ScriptEntry(val id: ScriptId, val source: String)

    fun catalog(builtIn: Map<String, String>, personal: Map<String, String>): List<ScriptEntry> =
        builtIn.map { (name, source) -> ScriptEntry(ScriptId(name, false), source) } +
            personal.toSortedMap().map { (name, source) -> ScriptEntry(ScriptId(name, true), source) }

    // An empty editor is a legitimate draft; a wrong preference type or
    // oversized value is not. Never silently truncate a script.
    fun restoreEditor(value: Any?, defaultSource: String): String =
        (value as? String)?.takeIf { it.length <= DptsScript.MAX_SOURCE_LENGTH }
            ?: defaultSource

    fun restoreEditorName(value: Any?): String =
        (value as? String)?.takeIf { it.length <= MAX_NAME_LENGTH &&
            it.none { char -> char.category in forbiddenNameCategories } }.orEmpty()

    fun preferenceKey(id: ScriptId): String? =
        if (id.personal && validName(id.name)) PREFIX + id.name else null

    private fun validName(name: String): Boolean =
        name.length in 1..MAX_NAME_LENGTH &&
            name == name.trim() && name.isNotBlank() &&
            name.none { it.category in forbiddenNameCategories }

    fun validDraft(name: String, source: String): Boolean =
        validName(name) && source.isNotBlank() && source.length <= DptsScript.MAX_SOURCE_LENGTH

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
