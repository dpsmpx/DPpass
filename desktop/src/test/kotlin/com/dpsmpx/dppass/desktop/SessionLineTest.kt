package com.dpsmpx.dppass.desktop

import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/** Первая строка «Журнала» ПК (D-87): версия и условия запуска — без идентификаторов (D-12). */
class SessionLineTest {
    @Test
    fun versionJavaAndArchOnly() {
        val line = DesktopGraph.sessionLine()
        assertTrue(line.startsWith("session_start version=${DesktopGraph.VERSION} java="), line)
        assertTrue("arch=" in line, line)
        val host = System.getenv("HOSTNAME")
        for (id in listOfNotNull(System.getProperty("user.name"), System.getProperty("user.home"), host)) {
            assertFalse(id.isNotBlank() && id in line, "в строке нет «$id»")
        }
    }
}
