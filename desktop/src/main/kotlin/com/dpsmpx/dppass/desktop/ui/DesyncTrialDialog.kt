package com.dpsmpx.dppass.desktop.ui

import com.dpsmpx.dppass.connection.HealthChecker
import com.dpsmpx.dppass.connection.TrialReport
import com.dpsmpx.dppass.connection.TrialSettings
import com.dpsmpx.dppass.connection.TrialSummary
import com.dpsmpx.dppass.desktop.DesktopGraph
import com.dpsmpx.dppass.desktop.DesktopPrefs
import com.dpsmpx.dppass.desktop.DesktopSession
import com.dpsmpx.dppass.desktop.SessionStatus
import com.dpsmpx.dppass.diagnostics.Outcome
import com.dpsmpx.dppass.diagnostics.Safe
import com.dpsmpx.dppass.network.NetworkType
import com.dpsmpx.dppass.network.RestrictionClass
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.awt.BorderLayout
import java.awt.FlowLayout
import java.awt.Frame
import java.awt.GridBagConstraints
import java.awt.GridBagLayout
import java.awt.Insets
import java.awt.event.WindowAdapter
import java.awt.event.WindowEvent
import javax.swing.JDialog
import javax.swing.JLabel
import javax.swing.JPanel
import javax.swing.JSpinner
import javax.swing.SpinnerNumberModel

/**
 * «Замер А/Б» на ПК (D-117, как D-116 на телефоне): к выбранному серверу, при
 * отключённом туннеле — без приёма, с разбиением ClientHello (D-68), с
 * перестановкой и с подделкой для каждого TTL диапазона, вперемешку по N
 * попыток с паузой 3 с. Итог — в окне и в «Журнале» (без адресов). Только
 * Linux: на Windows у моста нет `vmsplice`, и приёма там нет. Окно закрыто —
 * замер остановлен.
 */
class DesyncTrialDialog(
    owner: Frame,
    private val graph: DesktopGraph,
    private val session: DesktopSession,
    private val prefs: DesktopPrefs,
    private val scope: CoroutineScope,
) {
    private val dialog = JDialog(owner, "Замер А/Б", false)
    private val ttlFrom = JSpinner(SpinnerNumberModel(DEFAULTS.ttlFrom, 1, 64, 1))
    private val ttlTo = JSpinner(SpinnerNumberModel(DEFAULTS.ttlTo, 1, 64, 1))
    private val attempts = JSpinner(SpinnerNumberModel(DEFAULTS.attempts, 1, TrialSettings.MAX_ATTEMPTS, 1))
    private val server = Widgets.caption()
    private val progress = Widgets.caption()
    private val result = Widgets.still(Widgets.note())
    private val run = Widgets.button("Начать замер") { start() }
    private var job: Job? = null

    fun show() {
        val form = JPanel(GridBagLayout()).apply { isOpaque = false }
        var y = 0
        fun row(label: String, c: java.awt.Component) {
            form.add(JLabel(label), cell(0, y))
            form.add(c, cell(1, y).apply { fill = GridBagConstraints.HORIZONTAL; weightx = 1.0 })
            y++
        }
        val intro = Widgets.still(Widgets.note()).apply { text = INTRO }
        form.add(intro, cell(0, y++).apply { gridwidth = 2; fill = GridBagConstraints.HORIZONTAL })
        row("TTL подделки от", ttlFrom)
        row("TTL подделки до", ttlTo)
        row("Попыток каждого варианта", attempts)
        form.add(server, cell(0, y++).apply { gridwidth = 2 })
        val buttons = JPanel(FlowLayout(FlowLayout.LEFT, 0, 0)).apply {
            isOpaque = false
            add(run)
        }
        form.add(buttons, cell(0, y++).apply { gridwidth = 2 })
        form.add(progress, cell(0, y++).apply { gridwidth = 2 })
        form.add(result, cell(0, y).apply { gridwidth = 2; fill = GridBagConstraints.BOTH; weightx = 1.0; weighty = 1.0 })
        dialog.contentPane = JPanel(BorderLayout()).apply {
            background = Theme.palette.bg
            border = Widgets.pad(4)
            add(form, BorderLayout.CENTER)
        }
        dialog.addWindowListener(
            object : WindowAdapter() {
                override fun windowClosed(e: WindowEvent) = stop()

                override fun windowClosing(e: WindowEvent) = stop()
            },
        )
        dialog.defaultCloseOperation = JDialog.DISPOSE_ON_CLOSE
        dialog.setSize(WIDTH, HEIGHT)
        dialog.setLocationRelativeTo(dialog.owner)
        refresh()
        dialog.isVisible = true
    }

    private fun refresh() {
        val off = session.status.value.let { it is SessionStatus.Disconnected || it is SessionStatus.Failed }
        val name = profile()?.name
        server.text = when {
            name == null -> "Серверов нет: сначала добавьте подписку."
            !off -> "Отключите туннель: замер сам запускает ядро, без туннеля."
            else -> "Сервер: $name"
        }
        run.isEnabled = off && name != null && job?.isActive != true
    }

    private fun profile() = graph.core.activation.state.activeConfig?.let { ir ->
        prefs.selectedServer?.let { id -> ir.profiles.firstOrNull { it.id == id } } ?: ir.profiles.firstOrNull()
    }

    private fun start() {
        val core = graph.core
        val ir = core.activation.state.activeConfig ?: return
        val p = profile() ?: return
        val settings = TrialSettings(
            ttlFrom = (ttlFrom.value as Number).toInt(),
            ttlTo = (ttlTo.value as Number).toInt(),
            attempts = (attempts.value as Number).toInt(),
        )
        settings.problem()?.let {
            progress.text = "Замер не начат: $it"
            return
        }
        refresh()
        if (!run.isEnabled) return
        run.isEnabled = false
        result.text = ""
        val total = settings.variants().size * settings.attempts
        progress.text = "Попытка 0 из $total…"
        val timeout = (core.policy.healthTimeoutMillis - PROBE_MARGIN_MILLIS).toInt()
        val checker = HealthChecker { _, _ -> withContext(Dispatchers.IO) { graph.engine.probeHealth(ir.dns, timeout) } }
        val context = listOf<Pair<String, Any>>(
            "network" to (graph.host.network()?.type ?: NetworkType.NONE),
            "regime" to (graph.networkCheck.regime()?.restriction ?: RestrictionClass.UNKNOWN),
            "ttl_from" to settings.ttlFrom,
            "ttl_to" to settings.ttlTo,
        )
        job = scope.launch {
            var finished = false
            try {
                val r = core.desyncTrial().run(ir, p.id, checker, settings, context, pause = { delay(it) }) { done, all ->
                    scope.launch(Edt) { progress.text = "Попытка $done из $all…" }
                }
                finished = true
                withContext(Edt) {
                    when (r) {
                        is Outcome.Success -> {
                            progress.text = "Готово: итог — ниже и в «Журнале»."
                            result.text = TrialText.report(r.value)
                        }
                        is Outcome.Failure -> progress.text = "Замер не начат: ${r.errors.first().message}"
                    }
                }
            } finally {
                core.log.info("desync_trial_finished", "by" to Safe(if (finished) "done" else "left"))
                withContext(Edt + kotlinx.coroutines.NonCancellable) { refresh() }
            }
        }
    }

    private fun stop() {
        job?.cancel()
        job = null
    }

    private fun cell(x: Int, y: Int) = GridBagConstraints().apply {
        gridx = x
        gridy = y
        anchor = GridBagConstraints.WEST
        insets = Insets(Widgets.STEP, Widgets.STEP, Widgets.STEP, Widgets.STEP)
    }

    private companion object {
        val DEFAULTS = TrialSettings()
        const val PROBE_MARGIN_MILLIS = 2_000L
        const val WIDTH = 560
        const val HEIGHT = 620
        const val INTRO = "DPpass раз за разом подключается к выбранному серверу без туннеля: без приёма, с разбиением " +
            "ClientHello, с перестановкой (начало уходит с TTL 1) и с подделкой начала для каждого TTL из диапазона — " +
            "вперемешку, с паузой 3 с. Подделка с TTL больше расстояния до сервера доходит до сервера и рвёт соединение: " +
            "рост отказов при большом TTL ожидаем. Итог — наблюдение для этой сети на сегодня, а не обещание."
    }
}

/** Строки итога замера А/Б (D-116, D-117): вид, успехи, медиана, отказы, «без приёма». */
object TrialText {
    fun title(s: TrialSummary): String = when (s.variant) {
        "plain" -> "Без приёма"
        "split" -> "Разбиение ClientHello"
        "disorder" -> "Перестановка (TTL 1)"
        else -> "Подделка, TTL ${s.variant.removePrefix("fake-")}"
    }

    fun line(s: TrialSummary): String {
        val parts = mutableListOf("прошло: ${s.ok}/${s.total}")
        s.medianMillis?.let { parts += "медиана $it мс" }
        if (s.failures.isNotEmpty()) parts += s.failures.entries.joinToString(", ") { "${it.key.name}×${it.value}" }
        if (s.notApplied > 0) parts += "без приёма ${s.notApplied}×"
        return parts.joinToString(" · ")
    }

    fun report(r: TrialReport): String = r.summaries.joinToString("\n") { "${title(it)} — ${line(it)}" }
}
