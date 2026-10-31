package com.dpsmpx.dppass.desktop.ui

import com.dpsmpx.dppass.connection.DPpassCore
import com.dpsmpx.dppass.connection.ProviderPolicyStatus
import com.dpsmpx.dppass.subscriptions.Subscription
import com.dpsmpx.dppass.subscriptions.SubscriptionFetcher
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.awt.Component
import javax.swing.JOptionPane
import javax.swing.JTextArea

/**
 * «Маршрутизация поставщика» подписки на ПК (D-98) — то же, что на
 * телефоне: что действует, и включить — только после окна с тем, что
 * заменят правила и DNS поставщика и что останется своим (D-11).
 * Выключить — сразу.
 */
object ProviderPolicyDialog {
    fun show(
        parent: Component,
        core: DPpassCore,
        scope: CoroutineScope,
        sub: Subscription,
        fetcher: SubscriptionFetcher,
        appVersion: String,
        reconnect: () -> Unit,
        changed: () -> Unit,
    ) {
        val status = core.providerPolicyStatus(sub)
        if (status == ProviderPolicyStatus.OFF && !sub.providerPolicyOffered) {
            JOptionPane.showMessageDialog(parent, "Поставщик «${sub.displayName}» не присылал маршрутизацию и DNS.", TITLE, JOptionPane.INFORMATION_MESSAGE)
            return
        }
        val on = status == ProviderPolicyStatus.OFF
        val options = arrayOf(if (on) "Включить" else "Выключить", "Закрыть")
        val answer = JOptionPane.showOptionDialog(
            parent, area(describe(status, sub.displayName)), "$TITLE «${sub.displayName}»", JOptionPane.DEFAULT_OPTION, JOptionPane.PLAIN_MESSAGE,
            null, options, options.last(),
        )
        if (answer != 0) return
        scope.launch(Edt) {
            val r = withContext(Dispatchers.IO) { core.subscriptions.setProviderPolicy(sub.id, on, fetcher, appVersion) }
            SiteListsDialog.report(parent, r, reconnect, if (on) "Маршрутизация поставщика включена." else "Маршрутизация поставщика выключена.")
            changed()
        }
    }

    /** Текст окна: что действует; не включены — что заменят и что останется своим (согласие, D-11). */
    fun describe(status: ProviderPolicyStatus, name: String): String = when (status) {
        ProviderPolicyStatus.OFF -> "Не используется: действуют ваши маршрутизация и DNS.\n\n" + consent(name)
        ProviderPolicyStatus.IN_USE -> "Используется: действуют правила маршрутизации и DNS поставщика, ваши настройки — поверх."
        ProviderPolicyStatus.NOT_APPLIED -> "Включена, но подписка не применена: подействует, когда её применят."
        ProviderPolicyStatus.NOT_OFFERED -> "Включена, но поставщик сейчас не присылает маршрутизацию: действуют ваши маршрутизация и DNS."
    }

    fun consent(name: String): String =
        "Поставщик «$name» присылает свои маршрутизацию и DNS. Если их включить, то, пока применена эта подписка, правила, " +
            "действие по умолчанию и DNS поставщика заменят ваш режим маршрутизации, блокировку рекламы и резолвер DNS. " +
            "Ваши остаются: выбор приложений, локальная сеть мимо туннеля и свои списки сайтов — поверх правил поставщика. " +
            "Поставщик может менять правила с каждым обновлением подписки; выключить можно здесь же."

    private fun area(text: String) = JTextArea(text, ROWS, COLUMNS).apply {
        isEditable = false
        lineWrap = true
        wrapStyleWord = true
        caretPosition = 0
    }

    private const val TITLE = "Маршрутизация поставщика"
    private const val ROWS = 9
    private const val COLUMNS = 60
}
