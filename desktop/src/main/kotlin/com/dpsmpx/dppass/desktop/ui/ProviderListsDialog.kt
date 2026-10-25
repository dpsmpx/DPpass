package com.dpsmpx.dppass.desktop.ui

import com.dpsmpx.dppass.connection.DPpassCore
import com.dpsmpx.dppass.connection.ProviderListsView
import com.dpsmpx.dppass.routing.SiteLists
import com.dpsmpx.dppass.subscriptions.Subscription
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.awt.Component
import javax.swing.JOptionPane
import javax.swing.JScrollPane
import javax.swing.JTextArea

/**
 * «Списки поставщика» подписки на ПК (D-94) — то же, что на телефоне:
 * профиль маршрутизации поставщика хранится рядом со своими списками; здесь
 * — что в нём, что не взято и почему, что изменилось с прошлым профилем.
 * Включить — только после окна с тем, что в списках (D-11). Свои списки —
 * поверх.
 */
object ProviderListsDialog {
    fun show(parent: Component, core: DPpassCore, scope: CoroutineScope, sub: Subscription, reconnect: () -> Unit, changed: () -> Unit) {
        val view = core.providerLists(sub) ?: return JOptionPane.showMessageDialog(
            parent,
            "Поставщик «${sub.displayName}» не присылал профиль маршрутизации.",
            TITLE,
            JOptionPane.INFORMATION_MESSAGE,
        )
        val toggle = if (view.inUse) "Выключить" else "Использовать…"
        val options = if (view.profile != null || view.inUse) arrayOf(toggle, "Закрыть") else arrayOf("Закрыть")
        val area = JTextArea(describe(view, sub.displayName), ROWS, COLUMNS).apply {
            isEditable = false
            lineWrap = true
            wrapStyleWord = true
            caretPosition = 0
        }
        val answer = JOptionPane.showOptionDialog(
            parent, JScrollPane(area), "$TITLE «${sub.displayName}»", JOptionPane.DEFAULT_OPTION, JOptionPane.PLAIN_MESSAGE, null, options, options.last(),
        )
        if (options.size < 2 || answer != 0) return
        val on = !view.inUse
        if (on && !confirm(parent, view, sub.displayName)) return
        scope.launch(Edt) {
            val r = withContext(Dispatchers.IO) { core.subscriptions.setUseProviderLists(sub.id, on) }
            SiteListsDialog.report(parent, r, reconnect, if (on) "Списки поставщика включены." else "Списки поставщика выключены.")
            changed()
        }
    }

    /** Окно согласия (D-11): что будет вести сайты и что остаётся своим. */
    private fun confirm(parent: Component, view: ProviderListsView, name: String): Boolean {
        val lists = view.profile?.lists ?: return false
        val text = "Списки поставщика «$name» будут вести сайты: напрямую — ${lists.direct.size}, через туннель — ${lists.proxy.size}, " +
            "блокировать — ${lists.block.size}. Они обновляются вместе с подпиской, а что изменилось — видно в этом окне.\n\n" +
            "$OVER DNS, геоданные и режим маршрутизации — ваши.\n\nИспользовать?"
        val area = JTextArea(text, CONFIRM_ROWS, COLUMNS).apply {
            isEditable = false
            lineWrap = true
            wrapStyleWord = true
        }
        return JOptionPane.showConfirmDialog(parent, area, TITLE, JOptionPane.YES_NO_OPTION, JOptionPane.QUESTION_MESSAGE) == JOptionPane.YES_OPTION
    }

    /** Текст окна: профиль, действуют ли списки, сами списки, что изменилось, что не взято. */
    fun describe(view: ProviderListsView, name: String): String = buildString {
        val profile = view.profile
        append(profile?.name?.let { "Профиль «$it»" } ?: "Профиль поставщика «$name»")
        append(", получен ${Format.date(view.receivedAtMillis)}.\n")
        append(
            when {
                !view.inUse -> "Не используются: включить — кнопкой ниже."
                view.applied -> "Используются. $OVER"
                else -> "Включены, но подписка не применена: подействуют, когда её применят."
            },
        )
        view.problem?.let { append("\n\nПрофиль не разобран: ${it.message}") }
        if (profile == null) return@buildString
        for (kind in SiteLists.ORDER) {
            val list = profile.lists[kind]
            append("\n\n${SiteListsDialog.title(kind)} — ${list.size}:")
            if (!list.isEmpty) append("\n" + list.format())
        }
        append("\n\nЧто изменилось")
        val change = view.change
        when {
            change == null -> append(": первый профиль поставщика — сравнивать пока не с чем.")
            change.isEmpty -> append(": в списках ничего не изменилось.")
            else -> {
                view.previousAtMillis?.let { append(" (по сравнению с профилем от ${Format.date(it)})") }
                append(":")
                for (kind in SiteLists.ORDER) {
                    val title = SiteListsDialog.title(kind)
                    change.added[kind].takeIf { !it.isEmpty }?.let { append("\n+ «$title»: ${it.entries.joinToString { e -> e.text }}") }
                    change.removed[kind].takeIf { !it.isEmpty }?.let { append("\n− «$title»: ${it.entries.joinToString { e -> e.text }}") }
                }
            }
        }
        if (profile.skipped.isNotEmpty()) {
            append("\n\nНе взято:\n")
            append(profile.skipped.joinToString("\n") { "• ${it.field}: ${it.reason}" })
        }
    }

    private const val TITLE = "Списки поставщика"
    private const val OVER = "Свои списки сайтов — поверх: если запись есть и там, и там, решает своя."
    private const val ROWS = 24
    private const val CONFIRM_ROWS = 8
    private const val COLUMNS = 60
}
