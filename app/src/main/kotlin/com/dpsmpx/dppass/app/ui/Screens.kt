package com.dpsmpx.dppass.app.ui

import android.app.Activity
import android.os.Build
import android.view.Gravity
import android.view.View
import android.widget.LinearLayout
import android.widget.ScrollView
import com.dpsmpx.dppass.R
import com.dpsmpx.dppass.app.AppGraph
import com.dpsmpx.dppass.app.AppPrefs
import com.dpsmpx.dppass.app.TunnelStatus
import com.dpsmpx.dppass.diagnostics.Diagnostic
import kotlinx.coroutines.CoroutineScope
import java.text.DateFormat
import java.util.Date

/** Что экранам нужно от `MainActivity`: граф, область корутин и переходы. */
interface Host {
    val activity: Activity
    val scope: CoroutineScope

    /** Граф готов (собирается в фоне при запуске). */
    val graph: AppGraph.Graph?

    val prefs: AppPrefs

    fun connect()

    fun disconnect()

    /** Туннель есть или поднимается — переподключить с новой конфигурацией или выбором. */
    fun reconnectIfBusy()

    fun showTab(tab: Int)

    /** Вложенный экран поверх вкладок (настройки приложений, журнал, «О программе»); «Назад» — [pop]. */
    fun push(screen: Screen)

    fun pop()

    fun toast(text: CharSequence)

    /** Отказ с подробностями: заголовок и причина целиком, с цепочкой `causes` (D-22). */
    fun problem(title: CharSequence, reason: Diagnostic)

    /** Конфигурация, подписки или политика изменились: перерисовать видимое. */
    fun changed()

    /** Принесённый текст (буфер, файл, «Поделиться»): распознать и спросить (D-42). */
    fun importText(text: String)

    /** Выбрать файл для импорта (D-42). */
    fun pickFile()

    /** Выбрать картинку с QR-кодом для импорта (D-65): без разрешения камеры. */
    fun pickQrImage()

    /** QR-код камерой (D-71): разрешение «Камера» — при первом нажатии. */
    fun scanQr()

    /** Сохранить [text] в файл, который пользователь выберет системным диалогом (экспорт, D-11). */
    fun saveDocument(name: String, text: String)

    companion object {
        const val TAB_CONNECT: Int = 0
        const val TAB_SERVERS: Int = 1
        const val TAB_SUBSCRIPTIONS: Int = 2
        const val TAB_SETTINGS: Int = 3
    }
}

/**
 * Экран — представление и перерисовка по данным (D-34). Перерисовывается
 * только видимый экран; скрытый — при показе ([onShown]).
 */
abstract class Screen(protected val host: Host) {
    protected val context: Activity get() = host.activity

    abstract val view: View

    abstract fun render(status: TunnelStatus)

    /** Экран стал видимым: подписки на поток, таймеры. */
    open fun onShown() = Unit

    /** Экран скрыт: всё, что тикает, — остановить. */
    open fun onHidden() = Unit

    protected fun scroll(content: View, topDp: Int = 16): ScrollView = ScrollView(context).apply {
        isFillViewport = true
        clipToPadding = false
        val side = Ui.dp(context, 16)
        content.setPadding(side, Ui.dp(context, topDp), side, Ui.dp(context, 24))
        addView(content)
    }

    /** Шапка вкладки: крупный заголовок и действия справа. */
    protected fun header(title: CharSequence, vararg actions: View): LinearLayout = Ui.row(context).apply {
        minimumHeight = Ui.dp(context, 56)
        addView(
            Ui.text(context, R.style.Text_DPpass_Headline, title).apply {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) isAccessibilityHeading = true
            },
            Ui.weight(),
        )
        actions.forEach { addView(it) }
    }

    protected fun dateTime(millis: Long): String =
        DateFormat.getDateTimeInstance(DateFormat.SHORT, DateFormat.SHORT, context.resources.configuration.locales[0]).format(Date(millis))

    protected fun date(millis: Long): String =
        DateFormat.getDateInstance(DateFormat.MEDIUM, context.resources.configuration.locales[0]).format(Date(millis))

    protected fun bytes(n: Long): String =
        Formats.bytes(n, context.resources.getStringArray(R.array.units_bytes).toList(), context.resources.configuration.locales[0])

    protected fun speed(n: Long): String =
        Formats.speed(
            n,
            context.resources.getStringArray(R.array.units_bytes).toList(),
            context.resources.configuration.locales[0],
            context.getString(R.string.per_second),
        )
}

/** Вложенный экран: верхняя панель «Назад» и заголовок, ниже — прокрутка. */
abstract class SubScreen(host: Host, private val title: Int) : Screen(host) {
    protected abstract fun content(): View

    /** Содержимое — в прокрутке; false — во всю высоту под панелью (превью камеры, D-71). */
    protected open val scrolls: Boolean = true

    override val view: View by lazy {
        Ui.column(context).apply {
            setBackgroundColor(context.getColor(R.color.bg))
            addView(
                Ui.row(context).apply {
                    minimumHeight = Ui.dp(context, 56)
                    setPadding(Ui.dp(context, 4), 0, Ui.dp(context, 16), 0)
                    addView(Ui.iconButton(context, R.drawable.ic_back, context.getString(R.string.action_back)) { host.pop() })
                    addView(
                        Ui.text(context, R.style.Text_DPpass_Title, context.getString(title)).apply {
                            gravity = Gravity.CENTER_VERTICAL
                            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) isAccessibilityHeading = true
                        },
                        Ui.weight().apply { marginStart = Ui.dp(context, 4) },
                    )
                },
                Ui.matchWidth(),
            )
            addView(if (scrolls) scroll(content(), topDp = 8) else content(), LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, 0, 1f))
        }
    }
}
