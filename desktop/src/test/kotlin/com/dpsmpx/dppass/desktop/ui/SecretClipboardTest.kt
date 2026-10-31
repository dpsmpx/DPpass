package com.dpsmpx.dppass.desktop.ui

import java.awt.datatransfer.Clipboard
import java.awt.datatransfer.DataFlavor
import java.io.InputStream
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/** Пароли и журнал в буфере обмена (обзор 0.7.48, F-1): на Windows — с запретом истории и облачного буфера. */
class SecretClipboardTest {
    @Test
    fun onWindowsTextGoesWithHistoryAndCloudExclusionFormats() {
        val t = SecretClipboard.transferable("synthetic-password-01", windows = true)
        val flavors = t.transferDataFlavors.toList()
        assertEquals(DataFlavor.stringFlavor, flavors.first())
        assertEquals("synthetic-password-01", t.getTransferData(DataFlavor.stringFlavor))
        val marks = flavors.drop(1)
        assertEquals(3, marks.size)
        // Каждый вид данных — ровно тот формат Windows, имя которого регистрирует AWT.
        assertEquals(SecretClipboard.WINDOWS_FORMATS, marks.map { SecretClipboard.natives(it).single() })
        // DWORD 0: «не в историю», «не в облако».
        for (m in marks) {
            assertContentEquals(ByteArray(4), (t.getTransferData(m) as InputStream).readBytes(), m.mimeType)
        }
    }

    @Test
    fun elsewhereOnlyText() {
        // Как у AWT по умолчанию (StringSelection): только текст, форматов Windows нет.
        val t = SecretClipboard.transferable("synthetic-password-01", windows = false)
        assertEquals("synthetic-password-01", t.getTransferData(DataFlavor.stringFlavor))
        assertTrue(t.transferDataFlavors.none { "x-dppass-clipboard" in it.mimeType })
    }

    @Test
    fun copyPutsTextIntoTheGivenClipboard() {
        val clipboard = Clipboard("тест")
        SecretClipboard.copy("synthetic-password-01", clipboard, windows = true)
        assertEquals("synthetic-password-01", clipboard.getData(DataFlavor.stringFlavor))
        assertEquals(3, clipboard.availableDataFlavors.count { "x-dppass-clipboard" in it.mimeType }, "текст и три формата запрета")
        assertFalse(SecretClipboard.transferable("x", windows = true).isDataFlavorSupported(DataFlavor.imageFlavor))
    }
}
