package com.dpsmpx.dppass.desktop

import com.dpsmpx.dppass.connection.ProviderPolicyStatus
import com.dpsmpx.dppass.desktop.ui.ProviderPolicyDialog
import kotlin.test.Test
import kotlin.test.assertTrue

/** Окно «Маршрутизация поставщика» на ПК (D-98): состояние и согласие — что заменят и что останется своим. */
class ProviderPolicyDialogTest {
    @Test
    fun consentNamesWhatIsReplacedAndWhatStays() {
        val off = ProviderPolicyDialog.describe(ProviderPolicyStatus.OFF, "Дом")
        assertTrue("Не используется" in off, off)
        for (part in listOf("«Дом»", "режим маршрутизации", "блокировку рекламы", "резолвер DNS", "выбор приложений", "свои списки сайтов", "выключить")) {
            assertTrue(part in off, "в согласии нет «$part»: $off")
        }
        // Включены — согласие уже дано, текст — только что действует.
        val on = ProviderPolicyDialog.describe(ProviderPolicyStatus.IN_USE, "Дом")
        assertTrue("Используется" in on && "поверх" in on, on)
        assertTrue("не применена" in ProviderPolicyDialog.describe(ProviderPolicyStatus.NOT_APPLIED, "Дом"))
        assertTrue("не присылает" in ProviderPolicyDialog.describe(ProviderPolicyStatus.NOT_OFFERED, "Дом"))
    }
}
