package com.dpsmpx.dppass.app

/** Режим обычного автовыбора сервера подписки. */
internal enum class ServerAutoMode(val preferenceValue: String) {
    ADAPTIVE("adaptive"),
    PLANNER("planner"),
    FROZEN("frozen");

    companion object {
        fun fromPreference(value: String?): ServerAutoMode =
            entries.firstOrNull { it.preferenceValue == value } ?: ADAPTIVE
    }
}
