package com.dpsmpx.dppass.connection

import com.dpsmpx.dppass.config.ConfigIr
import com.dpsmpx.dppass.config.ConfigLoader
import com.dpsmpx.dppass.config.ConfigWriter
import com.dpsmpx.dppass.core.Checksums
import com.dpsmpx.dppass.core.Clock
import com.dpsmpx.dppass.core.Json
import com.dpsmpx.dppass.core.JsonArray
import com.dpsmpx.dppass.core.JsonNumber
import com.dpsmpx.dppass.core.JsonObject
import com.dpsmpx.dppass.core.JsonParseException
import com.dpsmpx.dppass.core.JsonString
import com.dpsmpx.dppass.core.ProfileId
import com.dpsmpx.dppass.diagnostics.DiagCode
import com.dpsmpx.dppass.diagnostics.Diagnostic
import com.dpsmpx.dppass.diagnostics.Outcome
import com.dpsmpx.dppass.engine.BackendCompiler
import com.dpsmpx.dppass.engine.CapabilityChecker
import com.dpsmpx.dppass.engine.CompilePlan
import com.dpsmpx.dppass.engine.CompiledConfig
import com.dpsmpx.dppass.engine.ProxyEngine
import com.dpsmpx.dppass.storage.BlobStore
import com.dpsmpx.dppass.storage.Quarantine
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock

enum class ActivationStatus { ACTIVE, SUPERSEDED, REJECTED, ROLLED_BACK }

/**
 * Шаги активации. [VALIDATION] — сохранённая конфигурация прочитается при
 * следующем запуске: та же проверка, что при восстановлении (D-07).
 */
enum class ActivationStep { VALIDATION, CAPABILITY, COMPILE, BACKEND_VALIDATION, HEALTH_CHECK, COMMIT }

/**
 * Запись истории активаций (D-07): версия, время, источник, контрольная
 * сумма, результат проверки, результат активации, причина отказа.
 */
data class ActivationRecord(
    val revision: Long,
    val timestampMillis: Long,
    val source: String,
    val sourceChecksum: String,
    val compiledChecksum: String?,
    val profileId: String?,
    val status: ActivationStatus,
    val failedStep: ActivationStep?,
    /** Код и сообщение причины отказа (без секретов). */
    val failure: String?,
)

/** Состояние активации целиком — одна атомарная запись в хранилище. */
data class ActivationState(
    val active: ActivationRecord?,
    val activeConfig: ConfigIr?,
    /** Предыдущая активная конфигурация — цель отката. */
    val previous: ActivationRecord?,
    val previousConfig: ConfigIr?,
    val history: List<ActivationRecord>,
    val nextRevision: Long,
) {
    companion object {
        val EMPTY: ActivationState = ActivationState(null, null, null, null, emptyList(), 1)
    }
}

sealed interface ActivationResult {
    val record: ActivationRecord
    val diagnostics: List<Diagnostic>

    data class Activated(override val record: ActivationRecord, override val diagnostics: List<Diagnostic>) : ActivationResult

    /** Отвергнуто; действующая конфигурация не тронута. */
    data class Rejected(override val record: ActivationRecord, override val diagnostics: List<Diagnostic>) : ActivationResult
}

/** Проверка здоровья перед заменой (опционально): запускает ядро на кандидате и смотрит полезную нагрузку. */
fun interface PreActivationCheck {
    suspend fun check(ir: ConfigIr, compiled: CompiledConfig): Outcome<Unit>
}

/**
 * Last-known-good (D-07). Любая смена конфигурации — транзакция:
 * возможности ядра → компиляция → проверка ядром → (здоровье) →
 * фиксация. Только полный успех делает NEW активной; до этого
 * действующая — та, что была. Отказ на любом шаге: NEW → REJECTED с
 * шагом и причиной, OLD остаётся ACTIVE.
 */
class ActivationService(
    private val compiler: BackendCompiler,
    private val engine: ProxyEngine,
    private val store: ActivationStore,
    private val clock: Clock,
    private val historyLimit: Int = 32,
) {
    private val mutations = Mutex()

    @Volatile
    var state: ActivationState = ActivationState.EMPTY
        private set

    /**
     * Почему писать нельзя: сохранённое состояние не прочитано и не
     * отложено в карантин (ключ хранилища недоступен, сбой чтения) —
     * запись затёрла бы действующую и предыдущую конфигурации и историю
     * (D-07). null — прочитано или отложено.
     */
    private var unreadable: List<Diagnostic>? = null
    private var restored = false

    /** Прочитать сохранённое состояние; повреждённое — в карантин, не «по умолчанию». */
    fun restore(): List<Diagnostic> {
        if (!mutations.tryLock()) return listOf(Diagnostic.error(DiagCode.ACTIVATION_REJECTED, "активация выполняется: восстановление отложено"))
        return try { restoreLocked() } finally { mutations.unlock() }
    }

    private fun restoreLocked(): List<Diagnostic> {
        val r = store.load()
        state = r.valueOrNull() ?: ActivationState.EMPTY
        unreadable = (r as? Outcome.Failure)?.diagnostics
        restored = true
        return r.diagnostics
    }

    /**
     * Перед любой записью: сохранённое должно быть прочитано. Не читали
     * или не прочиталось — ещё попытка (ключ хранилища мог вернуться);
     * находки чтения (например, карантин) идут в результат, а не теряются.
     */
    private fun ensureReadable(): Outcome<Unit> {
        if (restored && unreadable == null) return Outcome.Success(Unit)
        val notes = restoreLocked()
        return unreadable?.let { Outcome.Failure(it) } ?: Outcome.Success(Unit, notes)
    }

    private fun unreadableRejection(what: String, causes: List<Diagnostic>): Diagnostic =
        Diagnostic.error(DiagCode.ACTIVATION_REJECTED, "$what: сохранённое состояние не прочитано — запись затёрла бы его; ничего не записано")
            .copy(causes = causes.filter { it.isError })

    suspend fun activate(
        ir: ConfigIr,
        source: String,
        sourceChecksum: String,
        profileId: ProfileId? = null,
        withTun: Boolean = true,
        preCheck: PreActivationCheck? = null,
    ): ActivationResult = mutations.withLock { activateLocked(ir, source, sourceChecksum, profileId, withTun, preCheck) }

    private suspend fun activateLocked(
        ir: ConfigIr,
        source: String,
        sourceChecksum: String,
        profileId: ProfileId? = null,
        withTun: Boolean = true,
        preCheck: PreActivationCheck? = null,
    ): ActivationResult {
        val pid = profileId ?: ir.profiles.firstOrNull()?.id
        val readable = ensureReadable()
        if (readable is Outcome.Failure) {
            val record = ActivationRecord(
                state.nextRevision, clock.nowMillis(), source, sourceChecksum, null, pid?.value,
                ActivationStatus.REJECTED, ActivationStep.COMMIT, readable.errors.firstOrNull()?.let { "${it.code}: ${it.message}" },
            )
            return ActivationResult.Rejected(record, listOf(unreadableRejection("не активировано", readable.diagnostics)))
        }
        val restoreNotes = readable.diagnostics
        val revision = state.nextRevision
        fun reject(step: ActivationStep, diags: List<Diagnostic>, compiled: String? = null): ActivationResult.Rejected {
            val first = diags.firstOrNull { it.isError }
            val record = ActivationRecord(
                revision, clock.nowMillis(), source, sourceChecksum, compiled, pid?.value,
                ActivationStatus.REJECTED, step, first?.let { "${it.code}: ${it.message}" },
            )
            val top = Diagnostic.error(DiagCode.ACTIVATION_REJECTED, "конфигурация не активирована на шаге $step; действующая сохранена")
                .copy(causes = diags.filter { it.isError })
            commit(state.copy(history = trim(state.history + record), nextRevision = revision + 1))
            return ActivationResult.Rejected(record, listOf(top) + restoreNotes + diags.filter { !it.isError })
        }

        if (pid == null) return reject(ActivationStep.CAPABILITY, listOf(Diagnostic.error(DiagCode.PROFILES_EMPTY, "нет ни одного профиля")))
        // Сохраняется только то, что прочитается при следующем запуске (restore —
        // тот же ConfigLoader). Иначе конфигурация работала бы до перезапуска, а
        // потом всё состояние ушло бы в карантин (6 октября 2026 — повтор id в подписке).
        val loadable = ConfigLoader().load(ConfigWriter.write(ir, ConfigWriter.Mode.FULL))
        if (loadable is Outcome.Failure) return reject(ActivationStep.VALIDATION, loadable.diagnostics)
        val plan = CompilePlan(pid, withTun)
        val caps = CapabilityChecker.check(ir, compiler.capabilities, plan)
        if (caps.any { it.isError }) return reject(ActivationStep.CAPABILITY, caps)
        val compiled = when (val c = compiler.compile(ir, plan)) {
            is Outcome.Failure -> return reject(ActivationStep.COMPILE, c.diagnostics)
            is Outcome.Success -> c
        }
        val v = engine.validate(compiled.value)
        if (v is Outcome.Failure) return reject(ActivationStep.BACKEND_VALIDATION, v.diagnostics, compiled.value.checksum)
        // Находки проверки ядром (например, неполная проверка при работающем ядре, D-25) — не теряются.
        val notes = caps + compiled.diagnostics + v.diagnostics
        if (preCheck != null) {
            val h = preCheck.check(ir, compiled.value)
            if (h is Outcome.Failure) return reject(ActivationStep.HEALTH_CHECK, h.diagnostics, compiled.value.checksum)
        }
        val record = ActivationRecord(
            revision, clock.nowMillis(), source, sourceChecksum, compiled.value.checksum, pid.value,
            ActivationStatus.ACTIVE, null, null,
        )
        val superseded = state.active?.copy(status = ActivationStatus.SUPERSEDED)
        val next = ActivationState(
            active = record,
            activeConfig = ir,
            previous = superseded,
            previousConfig = state.activeConfig,
            history = trim(state.history + listOfNotNull(superseded) + record),
            nextRevision = revision + 1,
        )
        val saved = commit(next)
        if (saved is Outcome.Failure) {
            // Не удалось сохранить — значит, не активировано: состояние в памяти не меняется.
            return ActivationResult.Rejected(record.copy(status = ActivationStatus.REJECTED, failedStep = ActivationStep.COMMIT), saved.diagnostics)
        }
        return ActivationResult.Activated(record, restoreNotes + notes)
    }

    /**
     * Откат к предыдущей конфигурации: когда новая прошла проверки, но в
     * работе не передаёт данных (L7 «подключено, но пусто»).
     */
    fun rollback(reason: Diagnostic): Outcome<ActivationRecord> {
        if (!mutations.tryLock()) return Outcome.failure(DiagCode.ACTIVATION_REJECTED, "активация выполняется: повторите откат позднее")
        return try { rollbackLocked(reason) } finally { mutations.unlock() }
    }

    private fun rollbackLocked(reason: Diagnostic): Outcome<ActivationRecord> {
        val readable = ensureReadable()
        if (readable is Outcome.Failure) return Outcome.failure(unreadableRejection("откат не выполнен", readable.diagnostics))
        val prev = state.previous
        val prevConfig = state.previousConfig
        val current = state.active
        if (prev == null || prevConfig == null || current == null) {
            return Outcome.failure(DiagCode.NOTHING_TO_ROLL_BACK, "нет предыдущей конфигурации для отката")
        }
        val revision = state.nextRevision
        val rolledBack = current.copy(status = ActivationStatus.ROLLED_BACK, failure = "${reason.code}: ${reason.message}")
        val restored = prev.copy(
            revision = revision,
            timestampMillis = clock.nowMillis(),
            source = "rollback:${current.revision}",
            status = ActivationStatus.ACTIVE,
        )
        val next = ActivationState(restored, prevConfig, null, null, trim(state.history + rolledBack + restored), revision + 1)
        return when (val s = commit(next)) {
            is Outcome.Failure -> s
            is Outcome.Success -> Outcome.Success(
                restored,
                listOf(Diagnostic.warning(DiagCode.ROLLED_BACK_TO_LAST_KNOWN_GOOD, "возврат к ревизии ${prev.revision}: ${reason.code}")),
            )
        }
    }

    private fun trim(h: List<ActivationRecord>): List<ActivationRecord> = h.takeLast(historyLimit)

    private fun commit(next: ActivationState): Outcome<Unit> {
        val r = store.save(next)
        if (r is Outcome.Success) state = next
        return r
    }
}

/**
 * Хранение состояния активации одной записью (атомарность — от
 * [BlobStore]). Конфигурации внутри — документом DPpass с секретами:
 * на Android хранилище шифрованное (D-19).
 */
class ActivationStore(private val blobs: BlobStore, private val quarantine: Quarantine) {
    fun save(s: ActivationState): Outcome<Unit> {
        val doc = Json.obj(
            "format" to Json.str("dppass.activation"),
            "format_version" to Json.num(1),
            "next_revision" to Json.num(s.nextRevision),
            "active" to s.active?.let(::record),
            "active_config" to s.activeConfig?.let { ConfigWriter.toJson(it, ConfigWriter.Mode.FULL) },
            "previous" to s.previous?.let(::record),
            "previous_config" to s.previousConfig?.let { ConfigWriter.toJson(it, ConfigWriter.Mode.FULL) },
            "history" to Json.arr(s.history.map(::record)),
        )
        return blobs.write(KEY, Json.write(doc, pretty = false).toByteArray(Charsets.UTF_8))
    }

    fun load(): Outcome<ActivationState> {
        val bytes = when (val r = blobs.read(KEY)) {
            is Outcome.Failure -> return r
            is Outcome.Success -> r.value ?: return Outcome.Success(ActivationState.EMPTY)
        }
        val parsed = parse(String(bytes, Charsets.UTF_8))
        if (parsed is Outcome.Failure) {
            val reason = parsed.errors.first()
            // Начать с пустого можно, только когда исходник сохранён (D-06); не сохранился — читать нечего и писать нельзя.
            val kept = quarantine.keep("activation", bytes, reason)
            if (kept is Outcome.Failure) {
                return Outcome.Failure(
                    listOf(
                        Diagnostic.error(DiagCode.STORAGE_CORRUPTED, "состояние активации не прочитано и не сохранено в карантин")
                            .copy(causes = parsed.diagnostics + kept.diagnostics),
                    ),
                )
            }
            return Outcome.Success(
                ActivationState.EMPTY,
                listOf(
                    Diagnostic.warning(DiagCode.STORAGE_CORRUPTED, "состояние активации не прочитано; исходник сохранён в карантин, начато с пустого")
                        .copy(causes = parsed.diagnostics),
                ),
            )
        }
        return parsed
    }

    private fun parse(text: String): Outcome<ActivationState> {
        val root = try {
            Json.parse(text) as? JsonObject
        } catch (e: JsonParseException) {
            null
        } ?: return Outcome.failure(DiagCode.STORAGE_CORRUPTED, "не JSON-объект")
        if ((root["format"] as? JsonString)?.value != "dppass.activation" || (root["format_version"] as? JsonNumber)?.toIntOrNull() != 1) {
            return Outcome.failure(DiagCode.FORMAT_VERSION_UNSUPPORTED, "неизвестный формат состояния активации")
        }
        fun config(key: String): Outcome<ConfigIr?> {
            val c = root[key] as? JsonObject ?: return Outcome.Success(null)
            return when (val l = ConfigLoader().load(Json.write(c, pretty = false))) {
                is Outcome.Failure -> Outcome.Failure(l.diagnostics)
                is Outcome.Success -> Outcome.Success(l.value.ir, l.diagnostics)
            }
        }
        val active = config("active_config")
        if (active is Outcome.Failure) return active
        val previous = config("previous_config")
        if (previous is Outcome.Failure) return previous
        // Запись об активной или предыдущей конфигурации есть, но не читается —
        // состояние не цельное: отказ целиком (карантин, D-06), а не конфигурация
        // без записи о ней. Отсутствие записи (null не пишется) — норма.
        fun pinned(key: String): Outcome<ActivationRecord?> {
            val v = root[key] ?: return Outcome.Success(null)
            return (v as? JsonObject)?.let(::record)?.let { Outcome.Success(it) }
                ?: Outcome.failure(DiagCode.STORAGE_CORRUPTED, "запись $key не читается", "$.$key")
        }
        val activeRecord = pinned("active")
        if (activeRecord is Outcome.Failure) return activeRecord
        val previousRecord = pinned("previous")
        if (previousRecord is Outcome.Failure) return previousRecord
        // История — справка: нечитаемая запись пропускается, но с находкой.
        val found = mutableListOf<Diagnostic>()
        val history = (root["history"] as? JsonArray)?.items.orEmpty().mapIndexedNotNull { i, item ->
            val r = (item as? JsonObject)?.let(::record)
            if (r == null) found += Diagnostic.warning(DiagCode.STORAGE_CORRUPTED, "запись истории активаций не читается — пропущена", "$.history[$i]")
            r
        }
        // Номер ревизии не повторяется: без читаемого next_revision (или с меньшим,
        // чем уже выданные) счёт продолжается после самой поздней записи, а не с 1.
        val latest = listOfNotNull(activeRecord.valueOrNull(), previousRecord.valueOrNull()).plus(history).maxOfOrNull { it.revision } ?: 0
        val stored = (root["next_revision"] as? JsonNumber)?.toLongOrNull()
        val nextRevision = if (stored != null && stored > latest) {
            stored
        } else {
            found += Diagnostic.warning(
                DiagCode.STORAGE_CORRUPTED,
                "next_revision ${if (stored == null) "не читается" else "не больше выданных ревизий"} — счёт продолжен с ${latest + 1}",
                "$.next_revision",
            )
            latest + 1
        }
        return Outcome.Success(
            ActivationState(
                active = activeRecord.valueOrNull(),
                activeConfig = active.valueOrNull(),
                previous = previousRecord.valueOrNull(),
                previousConfig = previous.valueOrNull(),
                history = history,
                nextRevision = nextRevision,
            ),
            found,
        )
    }

    private fun record(r: ActivationRecord): JsonObject = Json.obj(
        "revision" to Json.num(r.revision),
        "timestamp" to Json.num(r.timestampMillis),
        "source" to Json.str(r.source),
        "source_checksum" to Json.str(r.sourceChecksum),
        "compiled_checksum" to Json.str(r.compiledChecksum),
        "profile" to Json.str(r.profileId),
        "status" to Json.str(r.status.name),
        "failed_step" to Json.str(r.failedStep?.name),
        "failure" to Json.str(r.failure),
    )

    private fun record(o: JsonObject): ActivationRecord? {
        fun s(k: String) = (o[k] as? JsonString)?.value
        fun n(k: String) = (o[k] as? JsonNumber)?.toLongOrNull()
        return ActivationRecord(
            revision = n("revision") ?: return null,
            timestampMillis = n("timestamp") ?: return null,
            source = s("source") ?: return null,
            sourceChecksum = s("source_checksum") ?: return null,
            compiledChecksum = s("compiled_checksum"),
            profileId = s("profile"),
            status = s("status")?.let { v -> ActivationStatus.entries.firstOrNull { it.name == v } } ?: return null,
            failedStep = s("failed_step")?.let { v -> ActivationStep.entries.firstOrNull { it.name == v } },
            failure = s("failure"),
        )
    }

    companion object {
        const val KEY: String = "activation/state"

        fun checksumOf(ir: ConfigIr): String = Checksums.sha256(ConfigWriter.write(ir, ConfigWriter.Mode.FULL))
    }
}
