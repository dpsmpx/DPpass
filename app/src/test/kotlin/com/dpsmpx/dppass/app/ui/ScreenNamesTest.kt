package com.dpsmpx.dppass.app.ui

import android.view.View
import android.view.ViewGroup
import android.widget.EditText
import android.widget.FrameLayout
import android.widget.ImageButton
import android.widget.ImageView
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.Switch
import android.widget.TextView
import java.io.File
import java.util.jar.JarFile
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * Методы экранов не совпадают с открытыми методами View ни по имени, ни
 * по числу параметров. Экраны строятся лямбдами внутри `apply` на View, а
 * там Kotlin отдаёт вызов ближайшему получателю — View, если у неё есть
 * такой метод, и делает это молча. Так 17 октября 2026 переключатель
 * «Раздавать туннель» звал `View.setEnabled` карточки вместо
 * `ShareScreen.setEnabled`: настройка не сохранялась, в журнале — ничего,
 * при следующей перерисовке переключатель снова выключен.
 */
class ScreenNamesTest {
    // Виды, на которых экраны вызывают `apply`: строительные блоки `Ui`.
    private val viewTypes = listOf(
        View::class.java, ViewGroup::class.java, LinearLayout::class.java, FrameLayout::class.java, ScrollView::class.java,
        TextView::class.java, EditText::class.java, ImageView::class.java, ImageButton::class.java, Switch::class.java,
    )

    // `context` экрана и `context` View — одна и та же Activity: подмена ничего не меняет.
    private val allowed = setOf("getContext" to 0)

    @Test
    fun screenMethodsDoNotShadowViewMethods() {
        val screens = screenClasses()
        assertTrue(screens.size >= 8 && ShareScreen::class.java in screens, "экраны не найдены: $screens")
        val viewMethods = viewTypes.flatMap { it.methods.toList() }.map { it.name to it.parameterCount }.toSet()
        val clashes = screens.flatMap { c ->
            c.declaredMethods
                .filter { !it.isSynthetic && !it.isBridge && '$' !in it.name }
                .map { it.name to it.parameterCount }
                .filter { it in viewMethods && it !in allowed }
                .map { (name, n) -> "${c.simpleName}.$name/$n" }
        }
        assertEquals(emptyList(), clashes.distinct(), "метод экрана совпадает с методом View — внутри apply на View вызов уйдёт в View")
    }

    /** Классы пакета `app.ui` — наследники [Screen] и он сам; из каталога классов или jar. */
    private fun screenClasses(): List<Class<*>> {
        val base = Screen::class.java
        val pkg = base.packageName.replace('.', '/') + "/"
        val location = base.protectionDomain?.codeSource?.location ?: error("не найти, откуда загружен ${base.name}")
        val root = File(location.toURI())
        val names = if (root.isDirectory) {
            File(root, pkg).list().orEmpty().toList()
        } else {
            JarFile(root).use { jar ->
                jar.entries().toList().map { it.name }.filter { it.startsWith(pkg) && '/' !in it.removePrefix(pkg) }.map { it.removePrefix(pkg) }
            }
        }
        return names.filter { it.endsWith(".class") && '$' !in it }
            .map { Class.forName(base.packageName + "." + it.removeSuffix(".class"), false, base.classLoader) }
            .filter { base.isAssignableFrom(it) }
    }
}
