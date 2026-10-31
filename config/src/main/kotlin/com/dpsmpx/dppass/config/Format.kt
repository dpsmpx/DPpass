package com.dpsmpx.dppass.config

import com.dpsmpx.dppass.core.JsonNumber
import com.dpsmpx.dppass.core.JsonObject
import com.dpsmpx.dppass.diagnostics.DiagCode
import com.dpsmpx.dppass.diagnostics.Diagnostic
import com.dpsmpx.dppass.diagnostics.Outcome

/**
 * Формат документа конфигурации DPpass (`docs/CONFIG_FORMAT.md`).
 *
 * Версия формата — своя и не связана с версиями Xray, sing-box,
 * геоданных или приложения (D-06).
 */
object ConfigFormat {
    const val MARKER: String = "dppass.config"
    const val CURRENT_VERSION: Int = 3

    /**
     * Производственные миграции. 1 → 2 (D-37) и 2 → 3 (D-107) —
     * тождественные: новая версия только добавляет значения и поля, а
     * прежние понимает так же. Их ждут документы, сохранённые на
     * устройстве до новой версии (D-07).
     */
    val MIGRATIONS: Map<Int, ConfigMigration> = mapOf(
        1 to ConfigMigration { doc -> Outcome.Success(JsonObject(doc.fields + ("format_version" to JsonNumber("2")))) },
        2 to ConfigMigration { doc -> Outcome.Success(JsonObject(doc.fields + ("format_version" to JsonNumber("3")))) },
    )
}

/** Пределы, после которых документ отвергается до разбора вглубь. */
data class ConfigLimits(
    val maxBytes: Int = 1 shl 20,
    val maxDepth: Int = 32,
    val maxProfiles: Int = 512,
    val maxRules: Int = 4096,
    val maxRuleValues: Int = 100_000,
    val maxStringLength: Int = 4096,
)

/**
 * Явная миграция документа между соседними версиями формата.
 *
 * Работает над деревом JSON до перевода в IR, не меняет исходный
 * документ (деревья неизменяемы) и обязана иметь тест (D-06).
 */
fun interface ConfigMigration {
    fun migrate(document: JsonObject): Outcome<JsonObject>
}

/**
 * Цепочка миграций до текущей версии.
 *
 * Правила (D-06): версия новее текущей — ошибка «создано более новой
 * версией»; версия, для которой нет миграции, — ошибка «не
 * поддерживается»; ни в одном случае не создаётся конфигурация по
 * умолчанию взамен — исходник сохраняется вызывающим и возвращается
 * пользователю вместе с причиной.
 *
 * Производственные миграции — [ConfigFormat.MIGRATIONS]; первая — 1 → 2
 * (D-37). Механизм проверен ещё и тестами на синтетической цепочке.
 */
class Migrator(
    private val currentVersion: Int = ConfigFormat.CURRENT_VERSION,
    private val migrations: Map<Int, ConfigMigration> = ConfigFormat.MIGRATIONS,
) {
    data class Result(val document: JsonObject, val fromVersion: Int)

    fun toCurrent(document: JsonObject): Outcome<Result> {
        val raw = document["format_version"]
            ?: return Outcome.failure(DiagCode.FORMAT_VERSION_MISSING, "нет поля format_version", "$.format_version")
        val version = (raw as? JsonNumber)?.toIntOrNull()
            ?: return Outcome.failure(DiagCode.FIELD_TYPE, "format_version должно быть целым числом", "$.format_version")
        if (version > currentVersion) {
            return Outcome.failure(
                DiagCode.FORMAT_VERSION_UNSUPPORTED,
                "документ создан более новой версией DPpass (формат $version, поддерживается до $currentVersion); исходник сохранён без изменений",
                "$.format_version",
            )
        }
        var doc = document
        val notes = mutableListOf<Diagnostic>()
        var v = version
        while (v < currentVersion) {
            val step = migrations[v] ?: return Outcome.failure(
                DiagCode.FORMAT_VERSION_UNSUPPORTED,
                "формат $v больше не поддерживается: миграции до $currentVersion нет; исходник сохранён без изменений",
                "$.format_version",
            )
            when (val r = step.migrate(doc)) {
                is Outcome.Failure -> return Outcome.Failure(
                    listOf(
                        Diagnostic.error(DiagCode.MIGRATION_FAILED, "миграция $v → ${v + 1} не удалась; исходник не изменён", "$")
                            .copy(causes = r.diagnostics),
                    ),
                )
                is Outcome.Success -> {
                    doc = r.value
                    notes += r.diagnostics
                    notes += Diagnostic.info(DiagCode.MIGRATION_APPLIED, "применена миграция $v → ${v + 1}")
                }
            }
            v++
        }
        return Outcome.Success(Result(doc, version), notes)
    }
}
