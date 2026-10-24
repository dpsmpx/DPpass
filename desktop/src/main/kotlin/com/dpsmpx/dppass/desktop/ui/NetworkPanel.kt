package com.dpsmpx.dppass.desktop.ui

import com.dpsmpx.dppass.desktop.DesktopNetworkCheck
import com.dpsmpx.dppass.diagnostics.Outcome
import com.dpsmpx.dppass.network.Confidence
import com.dpsmpx.dppass.network.NetworkAssessment
import com.dpsmpx.dppass.network.NetworkType
import com.dpsmpx.dppass.network.ProbeKind
import com.dpsmpx.dppass.network.ProbeOutcome
import com.dpsmpx.dppass.network.ProbeResult
import com.dpsmpx.dppass.network.ProbeTarget
import com.dpsmpx.dppass.network.RestrictionClass
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.launch
import java.awt.BorderLayout
import java.awt.FlowLayout
import javax.swing.DefaultListModel
import javax.swing.JList
import javax.swing.JPanel
import javax.swing.JScrollPane

/**
 * «Сеть» (D-79, к D-60): проверка сети ПК по кнопке — пробы к ориентирам
 * мимо туннеля, исходы по мере появления, вывод и его доводы. Итог идёт в
 * план только через память режима (D-64): белый список — порядок серверов
 * при следующем подключении.
 */
class NetworkPanel(private val check: DesktopNetworkCheck, private val scope: CoroutineScope) : JPanel(BorderLayout()) {
    private val model = DefaultListModel<String>()
    private val verdict = Widgets.title(" ")
    private val evidence = Widgets.caption()
    private val problem = Widgets.Banner(error = true)
    private val button = Widgets.button("Проверить сеть") { start() }

    init {
        background = Theme.palette.bg
        border = Widgets.pad(4)
        val top = JPanel(BorderLayout()).apply {
            isOpaque = false
            add(Widgets.title("Проверка сети").also { it.border = Widgets.pad(1) }, BorderLayout.NORTH)
            add(
                Widgets.note().apply {
                    text = "Пробы DNS, TCP, TLS, QUIC и крупной передачи к отечественному и двум зарубежным ориентирам — " +
                        "мимо туннеля, как без DPpass. Ориентиры видят адрес ПК, как при открытии сайта; ничего о вас в пробах нет. " +
                        "Если сеть похожа на белый список, при следующем подключении DPpass начнёт с серверов, которые под ним работали."
                },
                BorderLayout.CENTER,
            )
            add(
                JPanel(FlowLayout(FlowLayout.LEFT, Widgets.STEP * 2, Widgets.STEP * 2)).apply {
                    isOpaque = false
                    add(button)
                },
                BorderLayout.SOUTH,
            )
        }
        add(top, BorderLayout.NORTH)
        add(JScrollPane(JList(model)), BorderLayout.CENTER)
        add(
            JPanel(BorderLayout()).apply {
                isOpaque = false
                add(verdict, BorderLayout.NORTH)
                add(evidence, BorderLayout.CENTER)
                add(problem, BorderLayout.SOUTH)
            },
            BorderLayout.SOUTH,
        )
    }

    private fun start() {
        if (check.busy()) return
        val wait = check.readyInMillis()
        if (wait > 0) {
            problem.show("Пробы этой проверки ещё в пределе (D-14): повторите через ${(wait + 999) / 1000} с — раньше вышли бы пропуски, а не вывод.")
            return
        }
        problem.show(null)
        model.clear()
        verdict.text = "Проверяю…"
        evidence.text = " "
        button.isEnabled = false
        scope.launch(Edt) {
            val r = check.run(onResult = { result -> scope.launch(Edt) { model.addElement(line(result)) } })
            button.isEnabled = true
            when (r) {
                null -> verdict.text = "Проверка уже идёт (после смены сети) — итог будет в «Журнале»"
                is Outcome.Failure -> {
                    verdict.text = "Не проверено"
                    problem.show(Widgets.describe(r.errors.first()))
                }
                is Outcome.Success -> show(r.value)
            }
        }
    }

    private fun show(a: NetworkAssessment) {
        verdict.text = "${type(a.type)}: ${restriction(a.restriction)} (уверенность — ${confidence(a.confidence)})"
        evidence.text = "<html>" + a.evidence.joinToString("<br>") { esc(it) } + "</html>"
    }

    private companion object {
        fun line(r: ProbeResult): String {
            val ms = r.latencyMillis?.let { " · $it мс" }.orEmpty()
            return "${kind(r.request.kind)} · ${target(r.request.target)} · ${outcome(r.outcome)}$ms"
        }

        fun kind(k: ProbeKind): String = when (k) {
            ProbeKind.DNS -> "DNS"
            ProbeKind.TCP -> "TCP"
            ProbeKind.TLS -> "TLS"
            ProbeKind.UDP -> "QUIC"
            ProbeKind.CAPTIVE -> "Страница входа"
            ProbeKind.BULK -> "Крупная передача"
        }

        fun target(t: ProbeTarget): String = when (t) {
            ProbeTarget.DOMESTIC -> "отечественный"
            ProbeTarget.FOREIGN -> "зарубежный"
            ProbeTarget.FOREIGN_ALT -> "второй зарубежный"
        }

        fun outcome(o: ProbeOutcome): String = when (o) {
            ProbeOutcome.SUCCESS -> "прошла"
            ProbeOutcome.TIMEOUT -> "нет ответа"
            ProbeOutcome.RESET -> "сброс"
            ProbeOutcome.REFUSED -> "отказ"
            ProbeOutcome.DNS_TAMPERED -> "ответ DNS подменён"
            ProbeOutcome.STALLED -> "данные встали"
            ProbeOutcome.REDIRECTED -> "перенаправление на страницу входа"
            ProbeOutcome.UNREACHABLE -> "недоступен"
            ProbeOutcome.SKIPPED -> "пропущена (предел проб)"
            ProbeOutcome.INCONCLUSIVE -> "ничего не сказала"
        }

        fun type(t: NetworkType): String = when (t) {
            NetworkType.WIFI -> "Wi-Fi"
            NetworkType.MOBILE -> "Мобильная сеть"
            NetworkType.ETHERNET -> "Провод"
            NetworkType.OTHER -> "Сеть"
            NetworkType.NONE -> "Нет сети"
        }

        fun restriction(r: RestrictionClass): String = when (r) {
            RestrictionClass.UNKNOWN -> "непонятно"
            RestrictionClass.NORMAL -> "без заметных ограничений"
            RestrictionClass.DEGRADED -> "с помехами"
            RestrictionClass.ALLOWLIST_LIKE -> "похоже на белый список"
            RestrictionClass.CAPTIVE -> "нужен вход на странице сети"
            RestrictionClass.OFFLINE -> "нет связи"
        }

        fun confidence(c: Confidence): String = when (c) {
            Confidence.LOW -> "низкая"
            Confidence.MEDIUM -> "средняя"
            Confidence.HIGH -> "высокая"
        }

        fun esc(s: String) = s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    }
}
