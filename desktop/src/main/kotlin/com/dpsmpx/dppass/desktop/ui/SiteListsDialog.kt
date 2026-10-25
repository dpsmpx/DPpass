package com.dpsmpx.dppass.desktop.ui

import com.dpsmpx.dppass.connection.ActivationResult
import com.dpsmpx.dppass.connection.DPpassCore
import com.dpsmpx.dppass.connection.HappRoutingImport
import com.dpsmpx.dppass.diagnostics.Outcome
import com.dpsmpx.dppass.routing.SiteListKind
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.awt.BorderLayout
import java.awt.Component
import java.awt.GridLayout
import javax.swing.JCheckBox
import javax.swing.JLabel
import javax.swing.JOptionPane
import javax.swing.JPanel
import javax.swing.JScrollPane
import javax.swing.JTextArea

/**
 * «Свои списки сайтов» (D-93): напрямую, через туннель, блокировать —
 * запись на строку. Неверная строка, запись в двух списках или код, которого
 * нет в наборе геоданных, — ошибка, и окно открывается снова с тем же
 * текстом. Смена политики — в фоне; действует сразу — туннель
 * переподключается. Свои списки — слой поверх списков поставщика (D-94):
 * их можно выключить, не стирая.
 */
object SiteListsDialog {
    fun show(
        parent: Component,
        core: DPpassCore,
        scope: CoroutineScope,
        reconnect: () -> Unit,
        start: Map<SiteListKind, String>? = null,
        startEnabled: Boolean? = null,
    ) {
        val policy = core.userPolicy.currentOrDefault()
        val lists = policy.lists
        val texts = start ?: SiteListKind.entries.associateWith { lists[it].format() }
        val enabled = JCheckBox("Применять свои списки", startEnabled ?: policy.listsEnabled).apply {
            toolTipText = "Выключено — списки хранятся, но не действуют"
        }
        // Списки поставщика применённой подписки (D-94): свои идут раньше них.
        val provider = core.appliedSubscription()?.takeIf { it.providerProfile != null }?.let { sub ->
            "Списки поставщика «${sub.displayName}»: " +
                if (sub.useProviderLists) "включены — сначала свои списки, потом поставщика." else "получены, не используются (меню подписки)."
        }
        val areas = SiteListKind.entries.associateWith { JTextArea(texts.getValue(it), ROWS, COLUMNS) }
        val columns = JPanel(GridLayout(1, SiteListKind.entries.size, Widgets.STEP * 2, 0)).apply {
            for (kind in SiteListKind.entries) {
                add(
                    JPanel(BorderLayout(0, Widgets.STEP)).apply {
                        add(JLabel("<html><b>${title(kind)}</b><br>${note(kind)}</html>"), BorderLayout.NORTH)
                        add(JScrollPane(areas.getValue(kind)), BorderLayout.CENTER)
                    },
                )
            }
        }
        val form = JPanel(BorderLayout(0, Widgets.STEP * 2)).apply {
            add(enabled, BorderLayout.NORTH)
            add(columns, BorderLayout.CENTER)
            add(Widgets.note().apply { text = listOfNotNull(provider, NOTE).joinToString("\n\n"); this.columns = COLUMNS * 3 }, BorderLayout.SOUTH)
        }
        val answer = JOptionPane.showConfirmDialog(parent, form, "Свои списки сайтов", JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE)
        if (answer != JOptionPane.OK_OPTION) return
        val edited = areas.mapValues { it.value.text }
        val on = enabled.isSelected
        scope.launch(Edt) {
            val r = withContext(Dispatchers.IO) {
                core.userPolicy.setSiteLists(edited).let { saved ->
                    // Переключатель (D-94) — после списков: не сохранились списки — не меняется и он.
                    if (saved is Outcome.Success && on != core.userPolicy.currentOrDefault().listsEnabled) core.userPolicy.setListsEnabled(on) else saved
                }
            }
            // Не сохранено — окно снова, с тем же текстом.
            if (!report(parent, r, reconnect, null)) show(parent, core, scope, reconnect, edited, on)
        }
    }

    /** Профиль Happ (D-93): что добавится и что не будет взято; «Да» — добавить в свои списки. */
    fun confirmHapp(parent: Component, core: DPpassCore, scope: CoroutineScope, r: HappRoutingImport, reconnect: () -> Unit) {
        val skipped = r.skipped.take(SKIPPED_SHOWN).joinToString("\n") { "• ${it.field}: ${it.reason}" } +
            (r.skipped.size - SKIPPED_SHOWN).takeIf { it > 0 }?.let { "\n… и ещё $it" }.orEmpty()
        val text = (r.name?.let { "Профиль маршрутизации «$it».\n\n" } ?: "Профиль маршрутизации.\n\n") +
            "Добавится в свои списки сайтов: напрямую — ${r.lists.direct.size}, через туннель — ${r.lists.proxy.size}, " +
            "блокировать — ${r.lists.block.size}." +
            (if (skipped.isEmpty()) "" else "\n\nНе будет взято:\n$skipped") +
            "\n\nТа же запись из другого своего списка переедет туда, куда её отнёс профиль. DNS, геоданные и режим " +
            "маршрутизации не меняются.\n\nДобавить?"
        val area = JTextArea(text, ROWS, COLUMNS * 2).apply {
            isEditable = false
            lineWrap = true
            wrapStyleWord = true
        }
        val answer = JOptionPane.showConfirmDialog(parent, JScrollPane(area), "Импорт", JOptionPane.YES_NO_OPTION, JOptionPane.QUESTION_MESSAGE)
        if (answer != JOptionPane.YES_OPTION) return
        scope.launch(Edt) {
            report(parent, withContext(Dispatchers.IO) { core.userPolicy.addSiteLists(r.lists) }, reconnect, "Добавлено в свои списки сайтов.")
        }
    }

    /** Итог смены политики; true — готово (окно можно закрыть). */
    fun report(parent: Component, r: Outcome<ActivationResult?>, reconnect: () -> Unit, done: String?): Boolean {
        when (r) {
            is Outcome.Failure -> {
                JOptionPane.showMessageDialog(parent, r.errors.joinToString("\n") { it.message }, "Не сохранено", JOptionPane.WARNING_MESSAGE)
                return false
            }
            is Outcome.Success -> when (val a = r.value) {
                is ActivationResult.Rejected -> {
                    val why = a.diagnostics.filter { it.isError }.joinToString("\n\n") { Widgets.describe(it) }
                    JOptionPane.showMessageDialog(parent, why, "Не применено", JOptionPane.WARNING_MESSAGE)
                    return false
                }
                is ActivationResult.Activated -> reconnect()
                null -> Unit
            }
        }
        done?.let { JOptionPane.showMessageDialog(parent, it, "Импорт", JOptionPane.INFORMATION_MESSAGE) }
        return true
    }

    fun title(kind: SiteListKind): String = when (kind) {
        SiteListKind.DIRECT -> "Напрямую"
        SiteListKind.PROXY -> "Через туннель"
        SiteListKind.BLOCK -> "Блокировать"
    }

    private fun note(kind: SiteListKind): String = when (kind) {
        SiteListKind.DIRECT -> "мимо туннеля"
        SiteListKind.PROXY -> "через туннель, даже российские"
        SiteListKind.BLOCK -> "соединения отклоняются"
    }

    private const val ROWS = 12
    private const val COLUMNS = 24
    private const val SKIPPED_SHOWN = 12

    private const val NOTE = "Запись на строку: example.com (с поддоменами), full:www.example.com (только это имя), keyword:слово, " +
        "geosite:код, 203.0.113.7, 10.0.0.0/8, geoip:код; строки с # — заметки. Порядок: блокировать, через туннель, напрямую — " +
        "выигрывает более осторожное. Списки — раньше режима маршрутизации."
}
