package com.dpsmpx.dppass.desktop

import com.dpsmpx.dppass.connection.LocalProxyOffer
import com.dpsmpx.dppass.connection.LocalProxySettings
import com.dpsmpx.dppass.desktop.ui.LocalProxyDialog
import com.dpsmpx.dppass.diagnostics.DiagCode
import com.dpsmpx.dppass.diagnostics.Diagnostic
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** Подключение без VPN на ПК (D-95): строка панели и когда предлагать — как на телефоне. */
class LocalProxyDesktopTest {
    private val off = LocalProxySettings.generate()
    private val on = off.copy(enabled = true)

    @Test
    fun panelLineSaysWhereToPointPrograms() {
        assertNull(LocalProxyDialog.line(off, null), "выключено — строки нет")
        assertEquals("Без VPN включено · прокси 127.0.0.1:${on.port}", LocalProxyDialog.line(on, null))
        assertEquals("Без VPN · укажите в программах прокси 127.0.0.1:${on.port}", LocalProxyDialog.line(on, on.spec()))
        assertFalse(on.password.reveal() in LocalProxyDialog.line(on, on.spec())!!, "пароль — не в строке панели")
    }

    @Test
    fun offerOnlyWhenTunnelCannotBeRaisedAndModeIsOff() {
        val noTun = Diagnostic.error(DiagCode.TUN_ESTABLISH_FAILED, "у процесса нет права CAP_NET_ADMIN — туннель не поднять")
        assertTrue(LocalProxyOffer.applies(noTun, enabled = false))
        assertFalse(LocalProxyOffer.applies(noTun, enabled = true), "уже без VPN — предлагать нечего")
        val server = Diagnostic.error(DiagCode.HEALTH_CHECK_FAILED, "сервер не ответил")
        assertFalse(LocalProxyOffer.applies(server, enabled = false), "отказ сервера — без VPN не поможет")
    }
}
