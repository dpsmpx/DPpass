package com.dpsmpx.dppass.app

import android.content.ClipData
import android.content.ClipDescription
import android.content.ClipboardManager
import android.content.Context
import android.content.pm.ApplicationInfo
import android.os.Build
import android.os.PersistableBundle
import com.dpsmpx.dppass.core.Clock
import com.dpsmpx.dppass.diagnostics.CrashRecord
import com.dpsmpx.dppass.diagnostics.FileLogSink
import com.dpsmpx.dppass.diagnostics.LogEvent
import com.dpsmpx.dppass.diagnostics.LogExport
import com.dpsmpx.dppass.diagnostics.LogSink
import com.dpsmpx.dppass.diagnostics.Logger
import com.dpsmpx.dppass.diagnostics.MemoryLogSink
import com.dpsmpx.dppass.diagnostics.Safe
import com.dpsmpx.dppass.diagnostics.TeeLogSink
import java.io.File
import java.util.concurrent.Executors

/**
 * Журнал на устройстве (D-26): кольцо в памяти для локального отчёта и
 * файл в `noBackupFilesDir/log`, который пишется в фоне. Наружу журнал
 * уходит **только** явной кнопкой «Копировать журнал» (D-47): содержимое
 * буфера обмена читают другие приложения, поэтому автокопии при уходе с
 * экрана и остановке сервиса больше нет. Ничего не отправляется (D-12).
 *
 * Падение записывается всегда, даже с выключенным журналом: выключатель
 * отказывается от рутинных строк, а не от причины падения.
 */
object DeviceLog {
    private const val TITLE = "DPpass — журнал"
    private const val FLUSH_MILLIS = 500L

    /** Кольцо для локального отчёта (`DPpassCore.report`). */
    val memory = MemoryLogSink()

    @Volatile
    private var file: FileLogSink? = null

    @Volatile
    private var dir: File? = null

    /** Копия в буфер — не в главном потоке: файл читается целиком. */
    private val copier = Executors.newSingleThreadExecutor { r -> Thread(r, "dppass-log-copy").apply { isDaemon = true } }

    /** Приёмник для `DPpassCore` и `Logger` приложения: кольцо и (если включён) файл. */
    val sink: LogSink = TeeLogSink(memory, LogSink { e: LogEvent -> file?.emit(e) })

    val log: Logger = Logger("app", sink, Clock.SYSTEM::nowMillis)

    /** Один раз на процесс, первым делом в `DPpassApplication.onCreate`. */
    @Synchronized
    fun init(context: Context) {
        if (dir != null) return
        val d = File(context.noBackupFilesDir, "log").apply { mkdirs() }
        dir = d
        installCrashHandler(d)
        if (enabled(context)) open(context, d)
    }

    fun enabled(context: Context): Boolean {
        val flag = flagFile(context)
        if (!flag.isFile) return isDebuggable(context)
        return flag.readText().trim() == "1"
    }

    /** Переключатель оболочки; сам факт выключения остаётся в журнале. */
    @Synchronized
    fun setEnabled(context: Context, on: Boolean) {
        flagFile(context).writeText(if (on) "1" else "0")
        val d = dir ?: return
        if (on && file == null) {
            open(context, d)
            log.info("log_enabled")
        } else if (!on && file != null) {
            log.info("log_disabled")
            file?.close()
            file = null
        }
    }

    /**
     * Работа закончена (оболочка ушла с экрана, сервис остановлен):
     * отмечаем это в журнале. Наружу ничего не копируется — экспорт только
     * по явной кнопке (D-47): буфер обмена видят другие приложения.
     */
    fun onWorkFinished(context: Context, reason: String) {
        if (file == null) return
        log.info("work_finished", "reason" to Safe(reason))
    }

    /**
     * Кнопка «Копировать журнал»: копирует то, что есть, даже с выключенным
     * журналом — тогда события этого запуска из кольца памяти, те же, что
     * в локальном отчёте (D-54). [done] вызывается в фоновом потоке: число
     * скопированных символов или `null`, если копия не удалась.
     */
    fun copyToClipboard(context: Context, reason: String, done: (Int?) -> Unit) {
        val app = context.applicationContext
        copier.execute {
            val d = dir
            if (d == null) {
                done(null)
                return@execute
            }
            val open = file
            open?.flush(FLUSH_MILLIS)
            val text = LogExport.text(d, TITLE, memory = if (open == null) memory.snapshot() else null)
            val clip = ClipData.newPlainText(TITLE, text)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                // Android 13+: система не показывает предпросмотр текста журнала.
                clip.description.extras = PersistableBundle().apply { putBoolean(ClipDescription.EXTRA_IS_SENSITIVE, true) }
            }
            val ok = runCatching { app.getSystemService(ClipboardManager::class.java).setPrimaryClip(clip) }.isSuccess
            if (ok) {
                LogExport.clearCrash(d)
                log.info("log_copied", "reason" to Safe(reason), "chars" to text.length)
            }
            done(if (ok) text.length else null)
        }
    }

    private fun open(context: Context, d: File) {
        val sink = FileLogSink(d, Clock.SYSTEM::nowMillis)
        sink.startSession(header(context))
        file = sink
    }

    /** Условия запуска — без идентификаторов устройства (D-12): ни модели, ни серийного номера. */
    private fun header(context: Context): List<String> {
        val version = AppGraph.appVersion(context)
        val stamp = FileLogSink.stamp(Clock.SYSTEM.nowMillis())
        return listOf(
            "$stamp INFO app session_start version=$version api=${Build.VERSION.SDK_INT} " +
                "abis=${Build.SUPPORTED_ABIS.joinToString(",")} debuggable=${isDebuggable(context)}",
        )
    }

    private fun installCrashHandler(d: File) {
        val previous = Thread.getDefaultUncaughtExceptionHandler()
        Thread.setDefaultUncaughtExceptionHandler { thread, error ->
            CrashRecord.append(d, CrashRecord.render(thread.name, error, Clock.SYSTEM.nowMillis()))
            file?.flush(FLUSH_MILLIS)
            previous?.uncaughtException(thread, error)
        }
    }

    private fun flagFile(context: Context) = File(context.noBackupFilesDir, "log-enabled")

    private fun isDebuggable(context: Context): Boolean = (context.applicationInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE) != 0
}
