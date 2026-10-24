package com.dpsmpx.dppass.desktop

import com.dpsmpx.dppass.core.ProfileId
import java.io.File
import java.nio.file.Files
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** Настройки окна ПК: умолчания — как в решениях, выбор переживает перезапуск. */
class DesktopPrefsTest {
    private val dir: File = Files.createTempDirectory("dppass-prefs").toFile().also { it.deleteOnExit() }
    private val file = File(dir, "settings.properties")

    @Test
    fun defaultsFollowTheDecisions() {
        val p = DesktopPrefs(file)
        assertNull(p.selectedServer, "сервер — «автоматически» (D-15)")
        assertFalse(p.autoSwitch, "автопереключение — только с согласия (D-58)")
        assertTrue(p.checkOnNetworkChange, "проверка сети при её смене — включена, как выбрал автор (D-67, D-80)")
        assertFalse(p.splitClientHello, "разбиение ClientHello — выключено (D-68, D-81)")
    }

    @Test
    fun choicesSurviveRestart() {
        DesktopPrefs(file).apply {
            selectedServer = ProfileId("s1")
            autoSwitch = true
            checkOnNetworkChange = false
            splitClientHello = true
        }
        val again = DesktopPrefs(file)
        assertEquals(ProfileId("s1"), again.selectedServer)
        assertTrue(again.autoSwitch)
        assertFalse(again.checkOnNetworkChange)
        assertTrue(again.splitClientHello)
    }
}
