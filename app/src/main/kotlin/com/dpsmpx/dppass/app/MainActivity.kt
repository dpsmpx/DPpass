package com.dpsmpx.dppass.app

import android.app.Activity
import android.content.ClipboardManager
import android.content.Intent
import android.net.VpnService
import android.os.Bundle
import android.view.WindowManager
import android.widget.Button
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import android.widget.Toast
import com.dpsmpx.dppass.R
import com.dpsmpx.dppass.connection.ActivationResult
import com.dpsmpx.dppass.connection.DPpassCore
import com.dpsmpx.dppass.diagnostics.Outcome
import com.dpsmpx.dppass.routing.RouteQuery
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch

/**
 * Оболочка разработки: показывает, что конвейер DPpass работает на
 * Android — активация на ядре Xray (проверка без запуска), TunnelSpec,
 * решение маршрутизации, локальный отчёт; поднимает и останавливает
 * туннель. Своя конфигурация — документ DPpass из буфера обмена; пример
 * (синтетический) импортируется, только когда активной конфигурации нет,
 * — иначе он затирал бы свою при каждом открытии. Интерфейс продукта —
 * этап 4 `ROADMAP` (фреймворк UI — отложенное решение).
 */
class MainActivity : Activity() {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
    private lateinit var output: TextView

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // Экран может показать конфигурацию — снимки экрана запрещены (docs/SECURITY_MODEL.md, T9).
        window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)
        output = TextView(this).apply { setTextIsSelectable(true) }
        val start = Button(this).apply {
            setText(R.string.start_vpn)
            setOnClickListener { requestVpn() }
        }
        val stop = Button(this).apply {
            setText(R.string.stop_vpn)
            setOnClickListener { DPpassVpnService.stop(this@MainActivity) }
        }
        val paste = Button(this).apply {
            setText(R.string.import_clipboard)
            setOnClickListener { importClipboard() }
        }
        val copyLog = Button(this).apply {
            setText(R.string.copy_log)
            setOnClickListener { copyLog() }
        }
        val logToggle = Button(this)
        logToggle.setOnClickListener {
            DeviceLog.setEnabled(this, !DeviceLog.enabled(this))
            showLogState(logToggle)
        }
        showLogState(logToggle)
        val title = TextView(this).apply { setText(R.string.shell_title) }
        val note = TextView(this).apply { setText(R.string.shell_note) }
        val column = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            val pad = (16 * resources.displayMetrics.density).toInt()
            setPadding(pad, pad, pad, pad)
            addView(title)
            addView(note)
            addView(paste)
            addView(start)
            addView(stop)
            addView(copyLog)
            addView(logToggle)
            addView(output)
        }
        setContentView(ScrollView(this).apply { addView(column) })
        DeviceLog.log.info("activity_create")
        scope.launch { runShell() }
    }

    override fun onStop() {
        super.onStop()
        // Оболочка ушла с экрана — работа закончена: журнал в буфер обмена (D-26).
        // Поворот экрана — не уход.
        if (!isChangingConfigurations) DeviceLog.onWorkFinished(this, "activity_stop")
    }

    private fun showLogState(button: Button) {
        button.setText(if (DeviceLog.enabled(this)) R.string.log_on else R.string.log_off)
    }

    private fun copyLog() {
        DeviceLog.copyToClipboard(this, "button") { chars ->
            runOnUiThread {
                val text = if (chars != null) getString(R.string.log_copied, chars) else getString(R.string.log_copy_failed)
                Toast.makeText(this, text, Toast.LENGTH_SHORT).show()
            }
        }
    }

    private suspend fun runShell() {
        val core = AppGraph.core(this)
        val restored = core.restore()
        val lines = mutableListOf<String>()
        lines += "restore: ${if (restored.isEmpty()) "ok" else restored.joinToString { it.code.name }}"
        val active = core.activation.state.active
        if (active == null) {
            lines += "no active config — sample:"
            val sample = assets.open("sample/config.json").bufferedReader().use { it.readText() }
            lines += activationLines(core.importAndActivate(sample))
        } else {
            lines += "active revision ${active.revision}, profile ${active.profileId} (sample not imported)"
        }
        show(core, lines)
    }

    /** Документ DPpass из буфера обмена → активация; исходник остаётся у пользователя. */
    private fun importClipboard() {
        val clip = getSystemService(ClipboardManager::class.java).primaryClip
        val text = clip?.takeIf { it.itemCount > 0 }?.getItemAt(0)?.coerceToText(this)?.toString()
        if (text.isNullOrBlank()) {
            Toast.makeText(this, R.string.clipboard_empty, Toast.LENGTH_SHORT).show()
            return
        }
        scope.launch {
            val core = AppGraph.core(this@MainActivity)
            show(core, listOf("clipboard import:") + activationLines(core.importAndActivate(text)))
        }
    }

    private fun activationLines(r: Outcome<ActivationResult>): List<String> = when (r) {
        is Outcome.Failure -> listOf("rejected:") + r.errors.flatMap { it.renderWithCauses() }
        is Outcome.Success -> when (val a = r.value) {
            is ActivationResult.Activated -> listOf("activated revision ${a.record.revision}, profile ${a.record.profileId}")
            // Причина целиком, с текстом ядра: на устройстве её больше негде увидеть (D-22).
            is ActivationResult.Rejected -> listOf("rejected at ${a.record.failedStep}:") +
                a.diagnostics.filter { it.isError }.flatMap { it.renderWithCauses() }
        }
    }

    private fun show(core: DPpassCore, head: List<String>) {
        val lines = head.toMutableList()
        core.tunnelSpec()?.valueOrNull()?.let { lines += "tunnel spec: ${it.routes.size} routes, ${it.excludedRoutes.size} excluded, mtu ${it.mtu}" }
        core.explain(RouteQuery(domain = "ads.example.com"))?.let { lines += "route ads.example.com → ${it.action} (${it.reason})" }
        lines += ""
        lines += core.report().render()
        runOnUiThread { output.text = lines.joinToString("\n") }
    }

    private fun requestVpn() {
        val consent = VpnService.prepare(this)
        if (consent != null) {
            @Suppress("DEPRECATION") // без AndroidX нет Activity Result API; замена — вместе с выбором UI (этап 4)
            startActivityForResult(consent, REQUEST_VPN)
        } else {
            startService(Intent(this, DPpassVpnService::class.java))
        }
    }

    @Deprecated("Activity Result API — вместе с выбором UI (этап 4)")
    @Suppress("DEPRECATION")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == REQUEST_VPN && resultCode == RESULT_OK) startService(Intent(this, DPpassVpnService::class.java))
    }

    override fun onDestroy() {
        scope.cancel()
        super.onDestroy()
    }

    private companion object {
        const val REQUEST_VPN = 1
    }
}
