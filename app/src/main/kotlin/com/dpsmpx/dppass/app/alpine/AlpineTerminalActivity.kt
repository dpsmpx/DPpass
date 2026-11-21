package com.dpsmpx.dppass.app.alpine

import android.app.Activity
import android.graphics.Color
import android.graphics.Typeface
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.view.WindowManager
import android.view.inputmethod.EditorInfo
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import com.dpsmpx.dppass.app.alpine.terminal.Key
import com.dpsmpx.dppass.app.alpine.terminal.Mod
import com.dpsmpx.dppass.app.alpine.terminal.TerminalListener
import com.dpsmpx.dppass.app.alpine.terminal.TerminalSession
import com.dpsmpx.dppass.app.alpine.terminal.TerminalTransport
import kotlin.concurrent.thread

/**
 * Private local Alpine shell, based on DP_IDE's PRoot/PTY + terminal emulator.
 * Commands run with DPpass's Android UID; this is not system root.
 * Not attached to the VPN packet pipeline.
 */
class AlpineTerminalActivity : Activity() {
    private lateinit var status: TextView
    private lateinit var screen: TextView
    private lateinit var command: EditText
    private lateinit var openButton: Button
    private lateinit var installButton: Button
    private val main = Handler(Looper.getMainLooper())
    private var drawQueued = false
    private var closed = false

    @Volatile
    private var child: AlpineChild? = null

    private val session = TerminalSession(80, 24, scrollbackMax = 600, listener = object : TerminalListener {
        override fun changed() = redraw()
        override fun title(title: String) = redraw()
        override fun closed(exitCode: Int?) = message("Alpine: процесс завершён (код " + exitCode + ")")
    })

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)
        window.setSoftInputMode(WindowManager.LayoutParams.SOFT_INPUT_ADJUST_RESIZE)
        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(12, 12, 12, 12)
            setBackgroundColor(Color.rgb(15, 18, 24))
        }
        status = TextView(this).apply {
            textSize = 14f
            setTextColor(Color.WHITE)
            text = "Alpine / PRoot — root внутри Alpine не даёт root Android"
        }
        root.addView(status)
        val actions = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL }
        installButton = Button(this).apply {
            text = "Установить Alpine"
            setOnClickListener { install() }
        }
        openButton = Button(this).apply {
            text = "Открыть shell"
            setOnClickListener { openShell() }
        }
        actions.addView(installButton, LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f))
        actions.addView(openButton, LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f))
        root.addView(actions)
        root.addView(Button(this).apply {
            text = "Alpine: установить пакет (apk add)"
            setOnClickListener { addPackageDialog() }
        })
        screen = TextView(this).apply {
            typeface = Typeface.MONOSPACE
            textSize = 12f
            setTextColor(Color.rgb(230, 235, 240))
            setBackgroundColor(Color.BLACK)
            setPadding(8, 8, 8, 8)
            setTextIsSelectable(true)
            text = "Alpine не подключена."
        }
        val scroll = ScrollView(this).apply {
            fillViewport = true
            addView(screen)
        }
        root.addView(scroll, LinearLayout.LayoutParams(-1, 0, 1f))
        val keys = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL }
        for ((label, action) in listOf<Pair<String, () -> Unit>>(
            "Esc" to { session.key(Key.ESCAPE) },
            "Tab" to { session.key(Key.TAB) },
            "Ctrl+C" to { session.type("c", Mod.CTRL) },
            "↑" to { session.key(Key.UP) },
            "↓" to { session.key(Key.DOWN) },
            "←" to { session.key(Key.LEFT) },
            "→" to { session.key(Key.RIGHT) },
        )) {
            keys.addView(Button(this).apply { text = label; textSize = 10f; setOnClickListener { action() } },
                LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f))
        }
        root.addView(keys)
        val input = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL }
        command = EditText(this).apply {
            isSingleLine = true
            textSize = 15f
            hint = "Команда или текст для PTY"
            imeOptions = EditorInfo.IME_ACTION_SEND
            setTextColor(Color.WHITE)
            setHintTextColor(Color.LTGRAY)
            setOnEditorActionListener { _, _, _ -> submit(); true }
        }
        input.addView(command, LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f))
        input.addView(Button(this).apply { text = "↵"; setOnClickListener { submit() } })
        root.addView(input)
        setContentView(root)
        if (!AlpineRuntime.available(this)) {
            message("Alpine доступна только на arm64-v8a; исполняемый PRoot не найден.")
        } else if (AlpineRuntime.installed(this)) {
            installButton.isEnabled = false
            openShell()
        } else {
            message("Установите встроенный Alpine minirootfs; внешняя загрузка на телефоне не требуется.")
            openButton.isEnabled = false
        }
    }

    private fun addPackageDialog() {
        if (!AlpineRuntime.installed(this)) {
            message("Сначала установите Alpine")
            return
        }
        val entry = EditText(this).apply {
            hint = "Например: curl git"
            isSingleLine = true
        }
        android.app.AlertDialog.Builder(this)
            .setTitle("Установка пакетов Alpine")
            .setMessage("Выполняет apk add без /proc, как в DP_IDE. Установленное ПО не получает root Android.")
            .setView(entry)
            .setNegativeButton("Отмена", null)
            .setPositiveButton("Установить") { _, _ ->
                val names = entry.text.toString()
                message("Установка пакетов Alpine…")
                thread(name = "dppass-alpine-apk", isDaemon = true) {
                    val result = runCatching { AlpineRuntime.runPackages(applicationContext, "add", names) }
                    result.fold(
                        onSuccess = { (code, out) ->
                            message("apk add завершился: код $code")
                            main.post {
                                if (!closed) screen.text = out.takeLast(12000)
                            }
                        },
                        onFailure = { message("apk add: " + (it.message ?: it.javaClass.simpleName)) },
                    )
                }
            }
            .show()
    }

    private fun submit() {
        if (child == null) return
        val value = command.text.toString()
        command.setText("")
        session.type(value)
        session.key(Key.ENTER)
    }

    private fun install() {
        installButton.isEnabled = false
        openButton.isEnabled = false
        message("Проверка SHA-256 и установка Alpine в приватное хранилище…")
        thread(name = "dppass-alpine-install", isDaemon = true) {
            val result = runCatching { AlpineRuntime.install(applicationContext) }
            runOnUiThread {
                if (closed) return@runOnUiThread
                if (result.isSuccess) {
                    message("Alpine установлена. Доступен терминал.")
                    openButton.isEnabled = true
                } else {
                    message("Ошибка установки Alpine: " + (result.exceptionOrNull()?.message ?: "неизвестная ошибка"))
                    installButton.isEnabled = true
                }
            }
        }
    }

    private fun openShell() {
        if (child != null || !AlpineRuntime.installed(this)) return
        openButton.isEnabled = false
        message("Запуск PRoot и псевдотерминала…")
        thread(name = "dppass-alpine-shell", isDaemon = true) {
            val process = runCatching { AlpineRuntime.shell(applicationContext, 80, 24) }
                .getOrElse {
                    message("Не удалось запустить Alpine: " + (it.message ?: it.javaClass.simpleName))
                    runOnUiThread { if (!closed) openButton.isEnabled = true }
                    return@thread
                }
            if (closed) {
                process.stop()
                return@thread
            }
            child = process
            session.attach(object : TerminalTransport {
                override fun write(bytes: ByteArray) = process.send(bytes)
                override fun resize(cols: Int, rows: Int) = process.resize(cols, rows)
                override fun close() = process.stop()
            })
            message("Alpine запущена под UID приложения DPpass (PRoot -0).")
            try {
                val bytes = ByteArray(8192)
                while (!closed) {
                    val count = process.read(bytes)
                    if (count <= 0) break
                    session.output(bytes, 0, count)
                }
            } catch (_: java.io.IOException) {
                // A closed PTY is normal when the user exits or the Activity closes.
            } finally {
                val code = process.waitFor()
                session.closed(code)
                process.stop()
                if (child === process) child = null
                runOnUiThread { if (!closed) openButton.isEnabled = true }
            }
        }
    }

    private fun message(value: String) {
        runOnUiThread { if (!closed) status.text = value }
    }

    private fun redraw() {
        if (closed) return
        main.post {
            if (!drawQueued && !closed) {
                drawQueued = true
                main.postDelayed({
                    drawQueued = false
                    if (!closed) {
                        screen.text = session.read { emulator ->
                            val start = (emulator.lineCount - 80).coerceAtLeast(0)
                            (start until emulator.lineCount).joinToString("\n") { i -> emulator.line(i).text() }
                        }
                    }
                }, 40)
            }
        }
    }

    override fun onDestroy() {
        closed = true
        child?.stop()
        session.close()
        super.onDestroy()
    }
}
