package com.dpsmpx.dppass.app.device

import android.app.Activity
import android.os.Build
import android.view.View
import android.view.accessibility.AccessibilityNodeInfo
import android.widget.Switch
import com.dpsmpx.dppass.R
import com.dpsmpx.dppass.app.ui.Host
import com.dpsmpx.dppass.app.ui.Ui

/**
 * Доступность на настоящих видах (D-75): что слышит TalkBack и куда
 * попадает палец. На хосте этого не видно — только на телефоне.
 */
object AccessibilityTests : DeviceSuite {
    override val name = "Accessibility"

    override val cases = listOf(
        DeviceCase("everyTappableElementIsLabeledAndLargeEnough") { d ->
            val problems = mutableListOf<String>()
            onEachTab(d) { a, tab ->
                val min = d.dp(Ui.TOUCH_DP.toFloat()) - 1f
                for (v in d.views(a).filter { d.main { it.isClickable || it.isLongClickable } }) {
                    val (w, h, kind) = d.main { Triple(v.width, v.height, v.javaClass.simpleName) }
                    if (w == 0 && h == 0) continue
                    val label = d.label(v)
                    if (label.isBlank()) problems += "«$tab»: $kind без подписи для TalkBack"
                    if (w < min || h < min) problems += "«$tab»: «${label.take(30)}» ($kind) — ${dpOf(d, w)}×${dpOf(d, h)} dp, меньше ${Ui.TOUCH_DP}"
                }
            }
            expect(problems.isEmpty()) { problems.take(MAX_LISTED).joinToString("; ") + more(problems) }
        },
        DeviceCase("tabTitlesAreHeadings") { d ->
            // Заголовок для TalkBack — с Android 9; раньше проверять нечего.
            if (Build.VERSION.SDK_INT < Build.VERSION_CODES.P) return@DeviceCase
            val missing = mutableListOf<String>()
            onEachTab(d) { a, tab -> if (d.views(a).none { v -> d.main { v.isAccessibilityHeading } }) missing += tab }
            expect(missing.isEmpty()) { "без заголовка для TalkBack: ${missing.joinToString()}" }
        },
        DeviceCase("switchesTellTalkBackTheirState") { d ->
            val a = d.launch()
            d.waitUntil("граф приложения собран") { (a as Host).graph != null }
            d.tap(a, d.context.getString(R.string.tab_settings))
            var seen = 0
            for (v in d.views(a).filter { d.main { it.isClickable } }) {
                val (checkable, said, real) = d.main {
                    val info = v.createAccessibilityNodeInfo()
                    Triple(info.isCheckable, checked(info), switchIn(v)?.isChecked)
                }
                if (!checkable) continue
                seen++
                expect(real != null && said == real) {
                    "«${d.label(v).take(30)}»: TalkBack слышит «${if (said) "включено" else "выключено"}», а переключатель — ${real ?: "не найден"}"
                }
            }
            expect(seen > 0) { "в «Настройках» не нашлось ни одного переключателя для TalkBack" }
        },
    )

    /** Каждая вкладка по очереди: перейти и дать ей нарисоваться. */
    private fun onEachTab(d: Device, check: (Activity, String) -> Unit) {
        val a = d.launch()
        d.waitUntil("граф приложения собран") { (a as Host).graph != null }
        for (tab in LaunchTests.TABS) {
            val label = d.context.getString(tab)
            d.tap(a, label)
            check(a, label)
        }
    }

    private fun checked(info: AccessibilityNodeInfo): Boolean = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.BAKLAVA) {
        info.checked == AccessibilityNodeInfo.CHECKED_STATE_TRUE
    } else {
        // До Android 16 другого способа нет (как Ui.checkedState).
        @Suppress("DEPRECATION")
        info.isChecked
    }

    private fun switchIn(v: View): Switch? = when (v) {
        is Switch -> v
        is android.view.ViewGroup -> (0 until v.childCount).firstNotNullOfOrNull { switchIn(v.getChildAt(it)) }
        else -> null
    }

    private fun dpOf(d: Device, px: Int): Int = (px / d.dp(1f)).toInt()

    private fun more(all: List<String>): String = if (all.size > MAX_LISTED) " … и ещё ${all.size - MAX_LISTED}" else ""

    private const val MAX_LISTED = 10
}
