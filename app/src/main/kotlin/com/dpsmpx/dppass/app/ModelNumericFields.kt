package com.dpsmpx.dppass.app

/** Avoid the coercions in JSONObject/JSONArray getLong/getDouble. A stored
 * counter must be an integer JSON number, not a fraction or numeric string.
 * A sparse key has one canonical decimal spelling, as in the Go loader.
 */
internal object ModelNumericFields {
    fun integer(value: Any?): Long? = when (value) {
        is Int -> value.toLong()
        is Long -> value
        else -> null
    }

    fun observation(value: Any?): Boolean =
        integer(value)?.let { it in 0L..1_000_000_000L } == true

    fun weight(value: Any?): Boolean =
        value is Number && value.toDouble().let { it.isFinite() && kotlin.math.abs(it) <= 4.0 }

    fun sparseIndex(key: String, capacity: Long): Long? {
        val index = key.toLongOrNull() ?: return null
        return index.takeIf { it >= 0 && it < capacity && it.toString() == key }
    }
}
