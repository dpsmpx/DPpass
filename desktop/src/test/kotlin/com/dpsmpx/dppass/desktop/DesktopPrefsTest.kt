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
        assertTrue(p.splitSites().isEmpty, "сайты напрямую с разбиением — пусто (D-72, D-82)")
        assertNull(p.selectedRelay, "устройство раздачи — не выбрано: серверы, как обычно (D-55, D-85)")
    }

    @Test
    fun choicesSurviveRestart() {
        DesktopPrefs(file).apply {
            selectedServer = ProfileId("s1")
            autoSwitch = true
            checkOnNetworkChange = false
            splitClientHello = true
            splitSitesText = "example.com\ngeosite:youtube"
            selectedRelay = "a1b2c3"
        }
        val again = DesktopPrefs(file)
        assertEquals(ProfileId("s1"), again.selectedServer)
        assertTrue(again.autoSwitch)
        assertFalse(again.checkOnNetworkChange)
        assertTrue(again.splitClientHello)
        assertEquals(listOf("example.com"), again.splitSites().domains, "многострочный список переживает перезапуск")
        assertEquals(listOf("youtube"), again.splitSites().geoSites)
        assertEquals("a1b2c3", again.selectedRelay)
    }

    @Test
    fun damagedListIsEmptyNotHalfApplied() {
        DesktopPrefs(file).splitSitesText = "example.com\nне домен"
        assertTrue(DesktopPrefs(file).splitSites().isEmpty)
    }
}
