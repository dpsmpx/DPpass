package com.dpsmpx.dppass.config

import com.dpsmpx.dppass.core.JsonArray
import com.dpsmpx.dppass.core.JsonBool
import com.dpsmpx.dppass.core.JsonNull
import com.dpsmpx.dppass.core.JsonNumber
import com.dpsmpx.dppass.core.JsonObject
import com.dpsmpx.dppass.core.JsonString
import com.dpsmpx.dppass.core.JsonValue
import com.dpsmpx.dppass.diagnostics.DiagCode
import com.dpsmpx.dppass.diagnostics.DiagnosticCollector
import com.dpsmpx.dppass.diagnostics.Secret

/**
 * Чтение объекта документа с путём и находками.
 *
 * Каждое поле читается явно; в конце [finish] сообщает о полях, которые
 * никто не прочитал: в собственном формате DPpass неизвестное поле —
 * ошибка (D-06), потому что «незнакомое поле из будущей версии,
 * молча пропущенное» — это и есть молчаливая потеря смысла. Новые поля
 * появляются только вместе с новой версией формата.
 */
internal class ObjReader(private val obj: JsonObject, val path: String, private val diags: DiagnosticCollector) {
    private val used = HashSet<String>()

    fun has(key: String): Boolean = obj[key] != null

    private fun field(key: String, required: Boolean): JsonValue? {
        used += key
        val v = obj[key]
        if ((v == null || v == JsonNull) && required) diags.error(DiagCode.FIELD_MISSING, "нет обязательного поля «$key»", "$path.$key")
        return if (v == JsonNull) null else v
    }

    fun string(key: String, required: Boolean = true): String? = when (val v = field(key, required)) {
        null -> null
        is JsonString -> v.value
        else -> typeError(key, "строка")
    }

    fun secret(key: String, required: Boolean = true): Secret? = string(key, required)?.let(::Secret)

    fun int(key: String, required: Boolean = true, range: IntRange = Int.MIN_VALUE..Int.MAX_VALUE): Int? {
        val v = field(key, required) ?: return null
        val n = (v as? JsonNumber)?.toIntOrNull() ?: return typeError(key, "целое число")
        if (n !in range) {
            diags.error(DiagCode.FIELD_TYPE, "значение «$key» вне диапазона ${range.first}..${range.last}", "$path.$key")
            return null
        }
        return n
    }

    /** Целое до 2^63 (скорости и окна QUIC, формат 3); вне [range] — ошибка с путём. */
    fun long(key: String, required: Boolean = true, range: LongRange = Long.MIN_VALUE..Long.MAX_VALUE): Long? {
        val v = field(key, required) ?: return null
        val n = (v as? JsonNumber)?.toLongOrNull() ?: return typeError(key, "целое число")
        if (n !in range) {
            diags.error(DiagCode.FIELD_TYPE, "значение «$key» вне диапазона ${range.first}..${range.last}", "$path.$key")
            return null
        }
        return n
    }

    fun bool(key: String, default: Boolean): Boolean = when (val v = field(key, required = false)) {
        null -> default
        is JsonBool -> v.value
        else -> typeError(key, "true или false") ?: default
    }

    fun obj(key: String, required: Boolean = true): ObjReader? = when (val v = field(key, required)) {
        null -> null
        is JsonObject -> ObjReader(v, "$path.$key", diags)
        else -> typeError(key, "объект")
    }

    fun objects(key: String, required: Boolean = true): List<ObjReader> {
        val v = field(key, required) ?: return emptyList()
        val arr = v as? JsonArray ?: return typeError(key, "массив объектов") ?: emptyList()
        return arr.items.mapIndexedNotNull { i, item ->
            if (item is JsonObject) {
                ObjReader(item, "$path.$key[$i]", diags)
            } else {
                diags.error(DiagCode.FIELD_TYPE, "ожидался объект", "$path.$key[$i]")
                null
            }
        }
    }

    /** Список строк с путями элементов — для пометок по конкретному значению. */
    fun strings(key: String, required: Boolean = false): List<Pair<String, String>> {
        val v = field(key, required) ?: return emptyList()
        val arr = v as? JsonArray ?: return typeError(key, "массив строк") ?: emptyList()
        return arr.items.mapIndexedNotNull { i, item ->
            if (item is JsonString) {
                item.value to "$path.$key[$i]"
            } else {
                diags.error(DiagCode.FIELD_TYPE, "ожидалась строка", "$path.$key[$i]")
                null
            }
        }
    }

    /**
     * Диапазон (формат 2, D-37): целое «N» или строка «N» / «N-M», N ≤ M.
     * «0» — то же, что поля нет (так понимает Xray): null. Смысл значения
     * (например, начало не меньше 1) — `ConfigValidator`.
     */
    fun range(key: String): CountRange? {
        val v = field(key, required = false) ?: return null
        val parsed = when (v) {
            is JsonNumber -> v.toIntOrNull()?.takeIf { it >= 0 }?.let { CountRange(it, it) }
            is JsonString -> CountRange.parse(v.value)
            else -> return typeError(key, "целое или строка «N-M»")
        }
        if (parsed == null) {
            diags.error(DiagCode.TRANSPORT_SETTING_INVALID, "«$key» — целое «N» или «N-M» с N ≤ M, без знака", "$path.$key")
            return null
        }
        return parsed.takeUnless { it.from == 0 && it.to == 0 }
    }

    /** Значение из закрытого набора: неизвестное — ошибка, не «ближайшее похожее». */
    fun <E> enum(key: String, values: Map<String, E>, required: Boolean = true, default: E? = null): E? {
        val s = string(key, required) ?: return default
        return values[s] ?: run {
            diags.error(DiagCode.VALUE_UNKNOWN, "неизвестное значение «$key»; допустимо: ${values.keys.joinToString()}", "$path.$key")
            null
        }
    }

    fun finish() {
        for (k in obj.fields.keys) {
            if (k !in used) diags.error(DiagCode.FIELD_UNKNOWN, "неизвестное поле «$k»", "$path.$k")
        }
    }

    private fun <T> typeError(key: String, expected: String): T? {
        diags.error(DiagCode.FIELD_TYPE, "поле «$key» должно быть: $expected", "$path.$key")
        return null
    }
}
