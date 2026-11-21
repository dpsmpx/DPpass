package com.dpsmpx.dppass.app.alpine

import android.app.Activity
import android.os.Bundle
import android.view.Gravity
import android.view.WindowManager
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import com.dpsmpx.dpai.android.linux.NativeCalls
import com.dpsmpx.dppass.R
import kotlin.concurrent.thread

/**
 * Small in-app Alpine PTY console, based on DPmetaApp/dpai's native PTY ABI.
 * Runs under the Android application UID. This is NOT Android root and is
 * deliberately separate from DPpass's VPN dataplane.
 *
 * TERM=dumb keeps this small output view usable without shipping the IDE's
 * complete ANSI emulator. Full-screen TUI programs are not supported here.
 */
class AlpineTerminalActivity : Activity() {
    private lateinit var output: TextView
    private lateinit var scroll: ScrollView
    private lateinit var input: EditText
    private lateinit var start: Button
    @Volatile private var childPid: Int = -1
    @Volatile private var writer: Int = -1
    @Volatile private var reader: Int = -1
    @Volatile private var disposed: Boolean = false

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)
        title = getString(R.string.alpine_title)
        val pad = (12 * resources.displayMetrics.density).toInt()
        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(pad, pad, pad, pad)
        }
        start = Button(this).apply {
            text = getString(if (AlpineFiles.installed(this@AlpineTerminalActivity)) R.string.alpine_start else R.string.alpine_install)
            setOnClickListener { prepareOrStart() }
        }
        root.addView(start)
        scroll = ScrollView(this)
        output = TextView(this).apply {
            typeface = android.graphics.Typeface.MONOSPACE
            setTextIsSelectable(true)
            text = getString(R.string.alpine_note) + "\n"
            setTextColor(0xffe5e7eb.toInt())
            setBackgroundColor(0xff111827.toInt())
            setPadding(pad, pad, pad, pad)
        }
        scroll.addView(output)
        root.addView(scroll, LinearLayout.LayoutParams(-1, 0, 1f))
        val bottom = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL; gravity = Gravity.CENTER_VERTICAL }
        input = EditText(this).apply {
            hint = getString(R.string.alpine_command)
            isSingleLine = true
            isEnabled = false
        }
        bottom.addView(input, LinearLayout.LayoutParams(0, -2, 1f))
        val send = Button(this).apply {
            text = getString(R.string.alpine_send)
            setOnClickListener { sendInput("\n") }
        }
        bottom.addView(send)
        root.addView(bottom)
        val keys = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL }
        for ((label, data) in listOf("Tab" to "\t", "Esc" to "\u001b", "Ctrl-C" to "\u0003")) {
            keys.addView(Button(this).apply {
                text = label
                setOnClickListener { writePty(data) }
            }, LinearLayout.LayoutParams(0, -2, 1f))
        }
        root.addView(keys)
        setContentView(root)
        if (!AlpineFiles.supported(this)) {
            start.isEnabled = false
            append(getString(R.string.alpine_missing) + "\n")
        }
    }

    private fun prepareOrStart() {
        if (childPid > 0) return
        start.isEnabled = false
        if (AlpineFiles.installed(this)) {
            startShell()
        } else {
            append(getString(R.string.alpine_installing) + "\n")
            thread(name = "dppass-alpine-install", isDaemon = true) {
                val result = runCatching { AlpineFiles.install(applicationContext) }
                runOnUiThread {
                    if (disposed) return@runOnUiThread
                    if (result.isSuccess) {
                        append(getString(R.string.alpine_installed) + "\n")
                        start.text = getString(R.string.alpine_start)
                    } else {
                        append(getString(R.string.alpine_failed, result.exceptionOrNull()?.message.orEmpty()) + "\n")
                    }
                    start.isEnabled = true
                }
            }
        }
    }

    private fun startShell() {
        thread(name = "dppass-alpine-spawn", isDaemon = true) {
            val result = runCatching {
                AlpineFiles.refreshDns(applicationContext)
                val layout = AlpineFiles.layout(applicationContext)
                val fds = IntArray(3)
                val argv = AlpineArgs.shell(layout).map { it.toByteArray(Charsets.UTF_8) }.toTypedArray()
                val env = AlpineArgs.environment(layout).map { (key, value) ->
                    "$key=$value".toByteArray(Charsets.UTF_8)
                }.toTypedArray()
                val pid = NativeCalls.spawn(argv, env, null, 80, 26, fds)
                check(pid > 0) { if (pid < 0) NativeCalls.describe(-pid) else "invalid child PID" }
                Triple(pid, fds[0], fds[1])
            }
            runOnUiThread {
                val abandoned = result.getOrNull()
                if (disposed) {
                    if (abandoned != null) {
                        NativeCalls.kill(-abandoned.first, 15)
                        NativeCalls.close(abandoned.second)
                        NativeCalls.close(abandoned.third)
                    }
                    return@runOnUiThread
                }
                val session = abandoned
                if (session == null) {
                    append(getString(R.string.alpine_failed, result.exceptionOrNull()?.message.orEmpty()) + "\n")
                    start.isEnabled = true
                } else {
                    childPid = session.first
                    writer = session.second
                    reader = session.third
                    input.isEnabled = true
                    start.text = getString(R.string.alpine_running)
                    append(getString(R.string.alpine_started) + "\n")
                    watchSession(session.first, session.third)
                }
            }
        }
    }

    private fun watchSession(pid: Int, fd: Int) {
        thread(name = "dppass-alpine-output", isDaemon = true) {
            val buf = ByteArray(4096)
            while (true) {
                val n = NativeCalls.read(fd, buf, 0, buf.size)
                if (n <= 0) break
                val text = String(buf, 0, n, Charsets.UTF_8)
                    .replace(Regex("\u001b\\[[0-9;?]*[ -/]*[@-~]"), "")
                    .replace("\r", "")
                runOnUiThread { append(text) }
            }
            NativeCalls.close(fd)
        }
        thread(name = "dppass-alpine-wait", isDaemon = true) {
            val result = NativeCalls.waitFor(pid)
            runOnUiThread {
                if (disposed) return@runOnUiThread
                if (childPid == pid) {
                    childPid = -1
                    writer = -1
                    reader = -1
                    input.isEnabled = false
                    start.isEnabled = true
                    start.text = getString(R.string.alpine_start)
                    append(getString(R.string.alpine_exited, result) + "\n")
                }
            }
        }
    }

    private fun sendInput(suffix: String) {
        val text = input.text.toString() + suffix
        input.text.clear()
        writePty(text)
    }

    private fun writePty(value: String) {
        val fd = writer
        if (fd < 0) return
        val bytes = value.toByteArray(Charsets.UTF_8)
        thread(name = "dppass-alpine-input", isDaemon = true) {
            NativeCalls.write(fd, bytes, 0, bytes.size)
        }
    }

    private fun append(text: String) {
        val previous = output.text.toString()
        // Bound the UI log, never persist shell output or secrets on disk.
        output.text = (previous + text).takeLast(64 * 1024)
        scroll.post { scroll.fullScroll(ScrollView.FOCUS_DOWN) }
    }

    override fun onDestroy() {
        disposed = true
        val pid = childPid
        childPid = -1
        if (pid > 0) NativeCalls.kill(-pid, 15) // own session/process group
        val fd = writer
        writer = -1
        if (fd >= 0) NativeCalls.close(fd)
        super.onDestroy()
    }
}
