package com.dpsmpx.dppass.app.device

import android.widget.ScrollView
import com.dpsmpx.dppass.R
import com.dpsmpx.dppass.app.ui.Host
import com.dpsmpx.dppass.app.ui.PullToRefresh

/** Переходы и жесты (D-75): ничего не меняют, только открывают и закрывают. */
object NavigationTests : DeviceSuite {
    override val name = "Navigation"

    override val cases = listOf(
        DeviceCase("addSheetOpensAndClosesWithBack") { d ->
            val a = d.launch()
            d.waitUntil("граф приложения собран") { (a as Host).graph != null }
            d.tap(a, d.context.getString(R.string.tab_servers))
            d.tap(a, d.context.getString(R.string.add_title))
            // Лист — отдельное окно: пока он открыт, у экрана нет фокуса.
            d.waitUntil("открылся лист «Добавить»") { !a.hasWindowFocus() }
            d.back()
            d.waitUntil("лист «Добавить» закрылся по «Назад»") { a.hasWindowFocus() }
        },
        DeviceCase("pullDownAndBackDoesNotStartMeasuring") { d ->
            val a = d.launch()
            d.waitUntil("граф приложения собран") { (a as Host).graph != null }
            d.tap(a, d.context.getString(R.string.tab_servers))
            val pull = d.views(a).filterIsInstance<PullToRefresh>().singleOrNull()
            expect(pull != null) { "в «Серверах» нет протяжки вниз (D-70)" }
            pull!!
            // Список — в самом верху: протяжка работает только там. Прокрутка данных не меняет.
            d.main { (pull.getChildAt(0) as? ScrollView)?.scrollTo(0, 0) }
            // Палец — на заголовке экрана: там нет кнопок, которые нажались бы, не узнай жест протяжку.
            val from = d.dp(32f)
            d.drag(pull, from, from + d.dp(200f), thenY = from) {
                // Значок — второй вид протяжки: опустился под верх экрана.
                val (y, alpha) = d.main { pull.getChildAt(1).let { it.translationY to it.alpha } }
                expect(y > 0f && alpha > 0.9f) { "значок не опустился за пальцем: сдвиг $y, прозрачность $alpha" }
            }
            expect(!d.main { pull.refreshing }) { "палец вернулся наверх, а замер начался" }
        },
    )
}
