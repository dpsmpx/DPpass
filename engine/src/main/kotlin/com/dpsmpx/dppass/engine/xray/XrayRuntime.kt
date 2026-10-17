package com.dpsmpx.dppass.engine.xray

import com.dpsmpx.dppass.diagnostics.DiagCode
import com.dpsmpx.dppass.diagnostics.Diagnostic
import com.dpsmpx.dppass.diagnostics.ErrorSummary
import com.dpsmpx.dppass.diagnostics.Outcome
import com.dpsmpx.dppass.diagnostics.Redactor
import com.dpsmpx.dppass.engine.SocketProtector
import com.dpsmpx.dppass.engine.TrafficStats

/**
 * Нативная граница ядра Xray (D-25): то, что умеет мост `libdppassxray`
 * (`tools/xray/bridge`). Реализации — [JniXrayRuntime] и тестовые.
 *
 * Мост держит одно ядро на процесс; вызовы — короткие и блокирующие
 * (сборка конфигурации, запуск, остановка). Тексты отказов — сырые
 * тексты ядра, с возможными адресами и ключами из конфигурации: их
 * редактирует [XrayProxyEngine], а не реализация.
 */
interface XrayRuntime {
    /** Версия вкомпилированного ядра. */
    fun version(): String

    fun validate(config: ByteArray): XrayResult

    /**
     * Запуск. [tunFd] < 0 — без TUN. [protector] получает каждый исходящий
     * сокет ядра до соединения; с TUN он обязателен.
     */
    fun start(config: ByteArray, tunFd: Int, tunMtu: Int, protector: SocketProtector?): XrayResult

    /** Остановка; без запущенного ядра — [XrayResult.Ok]. */
    fun stop(): XrayResult

    /** Трафик исходящего `proxy` с запуска; `null` — ядро не запущено. */
    fun traffic(): TrafficStats?

    /**
     * Проба здоровья (D-32): запрос DNS к [target] через исходящий `proxy`
     * работающего ядра, в обход правил. Блокирует поток не дольше
     * [timeoutMillis].
     */
    fun probeDns(target: String, timeoutMillis: Int): DnsProbeResult

    /**
     * Замер через туннель (D-61): [pings] малых запросов к [target]
     * (`https://…`, путь с заданным объёмом ответа) и одна загрузка не
     * больше [maxBytes] и не дольше [maxTimeMillis] — по одному TLS-соединению
     * через исходящий `proxy`. Блокирует поток не дольше [timeoutMillis].
     */
    fun speedTest(target: String, pings: Int, maxBytes: Long, maxTimeMillis: Int, timeoutMillis: Int): SpeedProbeResult

    /**
     * Попадает ли [value] в `geosite:`[code] (имя байтами UTF-8) или в
     * `geoip:`[code] (адрес, 4 или 16 байт) набора геоданных (D-27) —
     * сопоставителем маршрутизатора ядра, по файлам каталога геоданных.
     * Ядро для этого не запускается. Первое обращение к коду читает файл
     * набора; потом сопоставитель берётся из памяти моста.
     */
    fun geoMatch(kind: GeoKind, code: String, value: ByteArray): GeoMatchResult
}

/** Вид кода геоданных; [code] — договор с `bridge.GeoKind` (Go). */
enum class GeoKind(val code: Int) {
    SITE(1),
    IP(2),
}

/** Ответ сопоставления с геоданными: [Answer] или отказ моста [XrayResult.Failed]. */
sealed interface GeoMatchResult {
    data class Answer(val matches: Boolean) : GeoMatchResult
}

/**
 * Ответ замера через туннель (D-61): исход — как у пробы DNS (тот же
 * `bridge.ProbeOutcome`), время каждого малого запроса, пришедшие байты
 * загрузки и её время; [text] — текст ядра без редактирования.
 */
class SpeedProbeResult(
    val outcome: DnsProbeOutcome,
    val pingMicros: List<Long>,
    val receivedBytes: Long,
    val transferMicros: Long,
    val text: String,
) {
    override fun toString(): String = "SpeedProbeResult($outcome, пингов ${pingMicros.size}, $receivedBytes байт за $transferMicros мкс)"
}

/** Исход пробы DNS; [code] — договор с `bridge.ProbeOutcome` (Go). */
enum class DnsProbeOutcome(val code: Int) {
    /** Ответ DNS на наш запрос пришёл через сервер профиля. */
    OK(0),

    /** Через сервер профиля не пришло ни байта. */
    UNREACHABLE(1),

    /** TLS с сервером DoH не установлен (сертификат, рукопожатие). */
    TLS(2),

    /** Байты шли, но ответа за срок нет — данные не идут (L7). */
    STALLED(3),

    /** Пришло не то: код HTTP не 200, чужой id, обрезанный ответ. */
    BAD_ANSWER(4),

    /** Ядро не запущено. */
    NOT_RUNNING(5),

    /** Цель пробы не понята. */
    CONTRACT(6),
    ;

    companion object {
        fun of(code: Int): DnsProbeOutcome = entries.firstOrNull { it.code == code } ?: CONTRACT
    }
}

/** Ответ пробы: исход, время до ответа, пришедшие байты; [text] — сырой текст ошибки (через [Redactor]). */
class DnsProbeResult(val outcome: DnsProbeOutcome, val elapsedMillis: Int, val receivedBytes: Int, val text: String) {
    override fun toString(): String = "DnsProbeResult($outcome, $elapsedMillis мс, $receivedBytes байт)"
}

/** Ответ моста. */
sealed interface XrayResult {
    data object Ok : XrayResult

    /** Проверка неполная: ядро занято, проверены только сборка и политика (D-25). */
    data object Partial : XrayResult

    /** [text] — сырой текст ядра: показывать только через [Redactor]. */
    class Failed(val kind: XrayFailureKind, val text: String) : XrayResult, GeoMatchResult {
        override fun toString(): String = "Failed($kind)"
    }
}

/** Вид отказа моста; [code] — договор с `bridge.Kind` (Go). */
enum class XrayFailureKind(val code: Int) {
    /** Конфигурация не собрана, не прошла политику моста или не принята ядром. */
    CONFIG(1),

    /** Конфигурация принята, ядро не запустилось или не остановилось. */
    START(2),

    /** Ядро уже запущено. */
    RUNNING(3),

    /** Нарушен договор вызова: fd, MTU, защитник, каталог геоданных, код или адрес сопоставления. */
    CONTRACT(4),
    ;

    companion object {
        fun of(code: Int): XrayFailureKind? = entries.firstOrNull { it.code == code }
    }
}

/**
 * Объявления JNI моста (`tools/xray/jni`). Договор: строки — байтами
 * UTF-8; ответ — байты, первый — статус (0 успех, 5 неполная проверка,
 * иначе [XrayFailureKind.code]), остальное — текст ядра; у пробы DNS и
 * сопоставления с геоданными — свои ответы ([decodeProbe], [decodeGeo]).
 * Вызывается только из [JniXrayRuntime].
 */
internal object XrayJni {
    @JvmStatic external fun nativeVersion(): ByteArray

    @JvmStatic external fun nativeSetAssetDir(dir: ByteArray): ByteArray

    @JvmStatic external fun nativeValidate(config: ByteArray): ByteArray

    @JvmStatic external fun nativeStart(config: ByteArray, tunFd: Int, tunMtu: Int, protector: SocketProtector?): ByteArray

    @JvmStatic external fun nativeStop(): ByteArray

    @JvmStatic external fun nativeTraffic(): LongArray?

    @JvmStatic external fun nativeProbeDns(target: ByteArray, timeoutMillis: Int): ByteArray

    @JvmStatic external fun nativeSpeedTest(target: ByteArray, pings: Int, maxBytes: Long, maxTimeMillis: Int, timeoutMillis: Int): ByteArray

    @JvmStatic external fun nativeGeoMatch(kind: Int, code: ByteArray, value: ByteArray): ByteArray

    /** Ответ сопоставления: статус 0 и байт 1 (попадает) или 0 (нет); отказ — как у [decode]. */
    fun decodeGeo(answer: ByteArray): GeoMatchResult = when (val r = decode(answer)) {
        is XrayResult.Failed -> r
        XrayResult.Ok -> when {
            answer.size == GEO_ANSWER && answer[1].toInt() == 1 -> GeoMatchResult.Answer(true)
            answer.size == GEO_ANSWER && answer[1].toInt() == 0 -> GeoMatchResult.Answer(false)
            else -> XrayResult.Failed(XrayFailureKind.CONTRACT, "ответ сопоставления не по договору: ${answer.size} байт")
        }
        XrayResult.Partial -> XrayResult.Failed(XrayFailureKind.CONTRACT, "ответ сопоставления со статусом неполной проверки")
    }

    /** Ответ пробы: исход, по 4 байта (старшим вперёд) время в мс и пришедшие байты, текст. */
    fun decodeProbe(answer: ByteArray): DnsProbeResult {
        if (answer.size < PROBE_HEADER) return DnsProbeResult(DnsProbeOutcome.CONTRACT, 0, 0, "короткий ответ пробы")
        val buf = java.nio.ByteBuffer.wrap(answer)
        val outcome = DnsProbeOutcome.of(buf.get().toInt())
        return DnsProbeResult(outcome, buf.getInt(), buf.getInt(), answer.decodeToString(PROBE_HEADER, answer.size))
    }

    /** Ответ замера: исход, число пингов, по 4 байта их мкс, 8 байт пришедшего, 4 байта мкс загрузки, текст. */
    fun decodeSpeed(answer: ByteArray): SpeedProbeResult {
        val bad = SpeedProbeResult(DnsProbeOutcome.CONTRACT, emptyList(), 0, 0, "ответ замера не по договору: ${answer.size} байт")
        if (answer.size < 2) return bad
        val count = answer[1].toInt() and 0xff
        val header = 2 + count * 4 + 8 + 4
        if (answer.size < header) return bad
        val buf = java.nio.ByteBuffer.wrap(answer)
        val outcome = DnsProbeOutcome.of(buf.get().toInt())
        buf.get()
        val pings = List(count) { buf.getInt().toLong() and 0xffff_ffffL }
        val received = buf.getLong()
        val transfer = buf.getInt().toLong() and 0xffff_ffffL
        return SpeedProbeResult(outcome, pings, received, transfer, answer.decodeToString(header, answer.size))
    }

    fun decode(answer: ByteArray): XrayResult {
        if (answer.isEmpty()) return XrayResult.Failed(XrayFailureKind.CONTRACT, "пустой ответ моста")
        val status = answer[0].toInt()
        val text = answer.decodeToString(1, answer.size)
        return when (status) {
            STATUS_OK -> XrayResult.Ok
            STATUS_PARTIAL -> XrayResult.Partial
            else -> XrayResult.Failed(XrayFailureKind.of(status) ?: XrayFailureKind.CONTRACT, text)
        }
    }

    private const val STATUS_OK = 0
    private const val STATUS_PARTIAL = 5
    private const val PROBE_HEADER = 9
    private const val GEO_ANSWER = 2
}

/** Мост через JNI: библиотека `libdppassxray.so` в этом процессе. */
class JniXrayRuntime private constructor() : XrayRuntime {
    override fun version(): String = XrayJni.nativeVersion().decodeToString()

    override fun validate(config: ByteArray): XrayResult = XrayJni.decode(XrayJni.nativeValidate(config))

    override fun start(config: ByteArray, tunFd: Int, tunMtu: Int, protector: SocketProtector?): XrayResult =
        XrayJni.decode(XrayJni.nativeStart(config, tunFd, tunMtu, protector))

    override fun stop(): XrayResult = XrayJni.decode(XrayJni.nativeStop())

    override fun traffic(): TrafficStats? = XrayJni.nativeTraffic()?.let { TrafficStats(uplinkBytes = it[0], downlinkBytes = it[1]) }

    override fun probeDns(target: String, timeoutMillis: Int): DnsProbeResult =
        XrayJni.decodeProbe(XrayJni.nativeProbeDns(target.encodeToByteArray(), timeoutMillis))

    override fun speedTest(target: String, pings: Int, maxBytes: Long, maxTimeMillis: Int, timeoutMillis: Int): SpeedProbeResult =
        XrayJni.decodeSpeed(XrayJni.nativeSpeedTest(target.encodeToByteArray(), pings, maxBytes, maxTimeMillis, timeoutMillis))

    override fun geoMatch(kind: GeoKind, code: String, value: ByteArray): GeoMatchResult =
        XrayJni.decodeGeo(XrayJni.nativeGeoMatch(kind.code, code.encodeToByteArray(), value))

    companion object {
        const val LIBRARY: String = "dppassxray"

        /**
         * Загрузка библиотеки, сверка версии ядра и каталог геоданных.
         * [loadLibrary] — на Android `System.loadLibrary(LIBRARY)`, на хосте
         * `System.load(путь)`. Любой отказ — `BACKEND_NOT_AVAILABLE`: ядро
         * другой версии не используется, компилятор пишет для одной (D-18).
         */
        fun load(loadLibrary: () -> Unit, assetDir: String): Outcome<XrayRuntime> {
            val version = try {
                loadLibrary()
                XrayJni.nativeVersion().decodeToString()
            } catch (e: UnsatisfiedLinkError) {
                return Outcome.failure(Diagnostic.fromThrowable(DiagCode.BACKEND_NOT_AVAILABLE, "библиотека ядра не загружена", e))
            } catch (e: SecurityException) {
                return Outcome.failure(Diagnostic.fromThrowable(DiagCode.BACKEND_NOT_AVAILABLE, "загрузка библиотеки ядра запрещена", e))
            }
            if (version != XrayBackend.VERSION) {
                return Outcome.failure(
                    DiagCode.BACKEND_NOT_AVAILABLE,
                    "в библиотеке ядра Xray $version, а компилятор пишет для ${XrayBackend.VERSION} (D-18)",
                )
            }
            return when (val r = XrayJni.decode(XrayJni.nativeSetAssetDir(assetDir.encodeToByteArray()))) {
                is XrayResult.Failed -> Outcome.failure(
                    Diagnostic.error(DiagCode.BACKEND_NOT_AVAILABLE, "ядру не задан каталог геоданных").withCause(r.cause(DiagCode.BACKEND_NOT_AVAILABLE)),
                )
                else -> Outcome.Success(JniXrayRuntime())
            }
        }
    }
}

/** Предел текста ядра в диагностике: длиннее — обрезается (отчёт не раздувается чужим текстом). */
internal const val CORE_TEXT_LIMIT: Int = 2000

/**
 * Отказ моста как причина диагностики (D-22): текст ядра — в
 * [ErrorSummary] после [Redactor], а не в сообщении.
 */
internal fun XrayResult.Failed.cause(code: DiagCode, redactor: Redactor = Redactor()): Diagnostic =
    Diagnostic(
        code = code,
        message = "ядро Xray: ${kind.name.lowercase()}",
        error = ErrorSummary("xray", redactor.redact(text.take(CORE_TEXT_LIMIT))),
    )
