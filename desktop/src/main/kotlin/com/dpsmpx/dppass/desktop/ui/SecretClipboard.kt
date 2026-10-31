package com.dpsmpx.dppass.desktop.ui

import com.dpsmpx.dppass.desktop.WindowsHost
import java.awt.Toolkit
import java.awt.datatransfer.Clipboard
import java.awt.datatransfer.DataFlavor
import java.awt.datatransfer.StringSelection
import java.awt.datatransfer.SystemFlavorMap
import java.awt.datatransfer.Transferable
import java.awt.datatransfer.UnsupportedFlavorException
import java.io.ByteArrayInputStream

/**
 * Буфер обмена для паролей и журнала (обзор 0.7.48, F-1; как пометка
 * «чувствительное» на Android, D-47). На Windows текст из буфера попадает в
 * историю (Win+V) и облачный буфер, если пользователь их включил. Windows
 * даёт форматы, которые это запрещают (`docs/research/WINDOWS_SHELL.md`,
 * §8): `ExcludeClipboardContentFromMonitorProcessing` и значение 0 в
 * `CanIncludeInClipboardHistory` и `CanUploadToCloudClipboard`. AWT на
 * Windows регистрирует незнакомое имя формата (`RegisterClipboardFormat`) и
 * кладёт его данные вместе с текстом, поэтому своего кода буфера не нужно:
 * достаточно сопоставить имена с видами данных. На Linux таких форматов нет
 * — там только текст.
 */
object SecretClipboard {
    /** Имена форматов Windows — так их и регистрирует система. */
    val WINDOWS_FORMATS: List<String> = listOf(
        "ExcludeClipboardContentFromMonitorProcessing",
        "CanIncludeInClipboardHistory",
        "CanUploadToCloudClipboard",
    )

    /** DWORD 0: «не в историю», «не в облако»; для первого формата годится любое значение. */
    private val ZERO = ByteArray(Int.SIZE_BYTES)

    /** Свой вид данных на каждый формат: сопоставление вида и имени — один к одному. */
    private val flavors: List<DataFlavor> by lazy {
        val map = SystemFlavorMap.getDefaultFlavorMap() as SystemFlavorMap
        WINDOWS_FORMATS.mapIndexed { i, native ->
            DataFlavor("application/x-dppass-clipboard-$i;class=java.io.InputStream", native).also {
                map.addUnencodedNativeForFlavor(it, native)
                map.addFlavorForUnencodedNative(native, it)
            }
        }
    }

    /** Положить [text] в системный буфер; на Windows — с запретом истории и облака. */
    fun copy(text: String, clipboard: Clipboard = Toolkit.getDefaultToolkit().systemClipboard, windows: Boolean = WindowsHost.isWindows()) {
        val content = transferable(text, windows)
        clipboard.setContents(content, content as? StringSelection)
    }

    /** Что кладётся в буфер: текст и, на Windows, форматы запрета. */
    fun transferable(text: String, windows: Boolean): Transferable = if (windows) Secret(text, flavors) else StringSelection(text)

    /** Имена форматов, сопоставленные виду данных [flavor] в карте AWT. */
    fun natives(flavor: DataFlavor): List<String> = (SystemFlavorMap.getDefaultFlavorMap() as SystemFlavorMap).getNativesForFlavor(flavor)

    private class Secret(private val text: String, private val marks: List<DataFlavor>) : Transferable {
        override fun getTransferDataFlavors(): Array<DataFlavor> = (listOf(DataFlavor.stringFlavor) + marks).toTypedArray()

        override fun isDataFlavorSupported(flavor: DataFlavor): Boolean = flavor == DataFlavor.stringFlavor || flavor in marks

        override fun getTransferData(flavor: DataFlavor): Any = when {
            flavor == DataFlavor.stringFlavor -> text
            flavor in marks -> ByteArrayInputStream(ZERO)
            else -> throw UnsupportedFlavorException(flavor)
        }
    }
}
