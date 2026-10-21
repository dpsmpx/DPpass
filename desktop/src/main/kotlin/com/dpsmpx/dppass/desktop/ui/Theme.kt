package com.dpsmpx.dppass.desktop.ui

import kotlinx.coroutines.CoroutineDispatcher
import java.awt.Color
import java.awt.Font
import java.io.File
import java.io.IOException
import javax.swing.SwingUtilities
import javax.swing.UIManager
import javax.swing.UnsupportedLookAndFeelException
import javax.swing.plaf.ColorUIResource
import javax.swing.plaf.FontUIResource
import javax.swing.plaf.metal.DefaultMetalTheme
import javax.swing.plaf.metal.MetalLookAndFeel
import kotlin.coroutines.CoroutineContext

/**
 * Токены цвета — те же, что у системы дизайна Android (D-34,
 * `app/src/main/res/values*` — colors.xml): облик DPpass один (D-01).
 */
data class Palette(
    val bg: Color,
    val surface: Color,
    val surfaceVariant: Color,
    val outline: Color,
    val text: Color,
    val textSecondary: Color,
    val primary: Color,
    val onPrimary: Color,
    val primaryContainer: Color,
    val success: Color,
    val successContainer: Color,
    val warning: Color,
    val warningContainer: Color,
    val error: Color,
    val errorContainer: Color,
) {
    companion object {
        val LIGHT = Palette(
            bg = rgb(0xF4F6FA), surface = rgb(0xFFFFFF), surfaceVariant = rgb(0xEBEEF5), outline = rgb(0xD8DCE6),
            text = rgb(0x11141B), textSecondary = rgb(0x586072), primary = rgb(0x2453C2), onPrimary = rgb(0xFFFFFF),
            primaryContainer = rgb(0xDCE5FF), success = rgb(0x187A4C), successContainer = rgb(0xD5F3E3),
            warning = rgb(0x9A5A00), warningContainer = rgb(0xFFEFD3), error = rgb(0xB3261E), errorContainer = rgb(0xFBE2E0),
        )
        val DARK = Palette(
            bg = rgb(0x0D0F14), surface = rgb(0x171A21), surfaceVariant = rgb(0x21252E), outline = rgb(0x2F3440),
            text = rgb(0xECEEF3), textSecondary = rgb(0xA6ACBA), primary = rgb(0x92B1FF), onPrimary = rgb(0x0B1D49),
            primaryContainer = rgb(0x213875), success = rgb(0x63D69F), successContainer = rgb(0x123F2A),
            warning = rgb(0xFFB95E), warningContainer = rgb(0x46320F), error = rgb(0xFF8C82), errorContainer = rgb(0x5A1E1A),
        )

        private fun rgb(v: Int) = Color(v)
    }
}

enum class ThemeChoice { AUTO, LIGHT, DARK }

object Theme {
    @Volatile
    var palette: Palette = Palette.DARK
        private set

    /**
     * Тема системы: KDE (`~/.config/kdeglobals`, схема цветов) или GTK
     * (`GTK_THEME` с `dark`). Не узнать — тёмная: тема Garuda по умолчанию тёмная.
     */
    fun systemIsDark(env: Map<String, String>, home: String): Boolean {
        env["GTK_THEME"]?.let { return it.contains("dark", ignoreCase = true) }
        val scheme = try {
            File(home, ".config/kdeglobals").readLines().firstOrNull { it.startsWith("ColorScheme=") }?.substringAfter('=')
        } catch (_: IOException) {
            null
        }
        return scheme?.contains("dark", ignoreCase = true) ?: true
    }

    /**
     * Metal со своей темой из токенов: Metal берёт цвета темы для всех
     * элементов (вкладки, меню, списки, диалоги), а не только для части.
     */
    fun apply(choice: ThemeChoice, env: Map<String, String>, home: String) {
        val dark = when (choice) {
            ThemeChoice.AUTO -> systemIsDark(env, home)
            ThemeChoice.LIGHT -> false
            ThemeChoice.DARK -> true
        }
        val p = if (dark) Palette.DARK else Palette.LIGHT
        palette = p
        MetalLookAndFeel.setCurrentTheme(TokenTheme(p))
        try {
            UIManager.setLookAndFeel(MetalLookAndFeel())
        } catch (_: UnsupportedLookAndFeelException) {
            return
        }
        val keys = mapOf(
            "Panel.background" to p.bg, "TabbedPane.selected" to p.surface, "TabbedPane.contentAreaColor" to p.bg,
            "TabbedPane.background" to p.surfaceVariant, "TabbedPane.foreground" to p.text, "TabbedPane.unselectedBackground" to p.surfaceVariant,
            "TabbedPane.tabAreaBackground" to p.bg, "TabbedPane.borderHightlightColor" to p.outline,
            "TabbedPane.highlight" to p.outline, "TabbedPane.light" to p.outline, "TabbedPane.darkShadow" to p.outline,
            "TabbedPane.selectHighlight" to p.outline, "TabbedPane.shadow" to p.outline, "TabbedPane.focus" to p.primary,
            "OptionPane.background" to p.bg, "OptionPane.messageForeground" to p.text, "ScrollPane.background" to p.bg,
            "Viewport.background" to p.surface, "Button.background" to p.surfaceVariant, "Button.foreground" to p.text,
            "List.selectionBackground" to p.primaryContainer, "List.selectionForeground" to p.text,
            "ToolTip.background" to p.surfaceVariant, "ToolTip.foreground" to p.text,
        )
        for ((k, v) in keys) UIManager.put(k, ColorUIResource(v))
        UIManager.put("Button.gradient", null)
        UIManager.put("MenuBar.gradient", null)
        UIManager.put("ToggleButton.gradient", null)
    }

    /** Тема Metal из токенов: «primary» — акцент, «secondary» — поверхности, «black» и «white» — текст и фон полей. */
    private class TokenTheme(private val p: Palette) : DefaultMetalTheme() {
        private val font = FontUIResource(Font.SANS_SERIF, Font.PLAIN, BASE_FONT)

        override fun getName(): String = "DPpass"

        override fun getPrimary1(): ColorUIResource = ColorUIResource(p.primary)

        override fun getPrimary2(): ColorUIResource = ColorUIResource(p.primary)

        override fun getPrimary3(): ColorUIResource = ColorUIResource(p.primaryContainer)

        override fun getSecondary1(): ColorUIResource = ColorUIResource(p.outline)

        override fun getSecondary2(): ColorUIResource = ColorUIResource(p.surfaceVariant)

        override fun getSecondary3(): ColorUIResource = ColorUIResource(p.bg)

        override fun getBlack(): ColorUIResource = ColorUIResource(p.text)

        override fun getWhite(): ColorUIResource = ColorUIResource(p.surface)

        override fun getControlTextColor(): ColorUIResource = ColorUIResource(p.text)

        override fun getInactiveControlTextColor(): ColorUIResource = ColorUIResource(p.textSecondary)

        override fun getUserTextColor(): ColorUIResource = ColorUIResource(p.text)

        override fun getSystemTextColor(): ColorUIResource = ColorUIResource(p.text)

        override fun getMenuForeground(): ColorUIResource = ColorUIResource(p.text)

        override fun getMenuBackground(): ColorUIResource = ColorUIResource(p.surface)

        override fun getMenuSelectedBackground(): ColorUIResource = ColorUIResource(p.primaryContainer)

        override fun getMenuSelectedForeground(): ColorUIResource = ColorUIResource(p.text)

        override fun getHighlightedTextColor(): ColorUIResource = ColorUIResource(p.text)

        override fun getControlTextFont(): FontUIResource = font

        override fun getMenuTextFont(): FontUIResource = font

        override fun getSystemTextFont(): FontUIResource = font

        override fun getUserTextFont(): FontUIResource = font

        override fun getWindowTitleFont(): FontUIResource = font

        override fun getSubTextFont(): FontUIResource = font
    }

    const val BASE_FONT: Int = 14
}

/** Диспетчер корутин для потока событий Swing: без лишней зависимости (D-20). */
object Edt : CoroutineDispatcher() {
    override fun dispatch(context: CoroutineContext, block: Runnable) {
        if (SwingUtilities.isEventDispatchThread()) block.run() else SwingUtilities.invokeLater(block)
    }

    override fun isDispatchNeeded(context: CoroutineContext): Boolean = !SwingUtilities.isEventDispatchThread()
}
