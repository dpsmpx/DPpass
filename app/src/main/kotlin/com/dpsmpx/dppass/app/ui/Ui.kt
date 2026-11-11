package com.dpsmpx.dppass.app.ui

import android.annotation.SuppressLint
import android.app.Activity
import android.app.AlertDialog
import android.app.Dialog
import android.content.ClipData
import android.content.ClipDescription
import android.content.ClipboardManager
import android.content.Context
import android.content.res.ColorStateList
import android.graphics.Canvas
import android.graphics.Color
import android.graphics.Paint
import android.graphics.RectF
import android.graphics.drawable.ColorDrawable
import android.graphics.drawable.GradientDrawable
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.os.PersistableBundle
import android.text.Editable
import android.text.InputType
import android.text.TextUtils
import android.text.TextWatcher
import android.util.TypedValue
import android.view.Gravity
import android.view.View
import android.view.ViewGroup
import android.view.Window
import android.view.WindowManager
import android.view.accessibility.AccessibilityEvent
import android.view.accessibility.AccessibilityNodeInfo
import android.widget.Button
import android.widget.EditText
import android.widget.FrameLayout
import android.widget.ImageView
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.Switch
import android.widget.TextView
import com.dpsmpx.dppass.R
import com.dpsmpx.dppass.diagnostics.FailureKind
import kotlinx.coroutines.CoroutineDispatcher
import kotlin.coroutines.CoroutineContext
import kotlin.math.roundToInt

/**
 * Главный поток как диспетчер корутин. `kotlinx-coroutines-android` ради
 * одного диспетчера не подключается: новая зависимость — по D-18, а
 * интерфейс — без библиотек (D-34).
 */
object MainThread : CoroutineDispatcher() {
    private val handler = Handler(Looper.getMainLooper())

    override fun dispatch(context: CoroutineContext, block: Runnable) {
        handler.post(block)
    }
}

/**
 * Строительные блоки экранов (D-34): размеры — шагом 4 dp, касаемая
 * область — не меньше 48 dp, цвета — токены `values*`/colors.xml, текст —
 * стили `Text.DPpass.*`.
 */
internal object Ui {
    const val TOUCH_DP: Int = 48

    fun dp(context: Context, value: Int): Int = (value * context.resources.displayMetrics.density).roundToInt()

    fun dpF(context: Context, value: Float): Float = TypedValue.applyDimension(TypedValue.COMPLEX_UNIT_DIP, value, context.resources.displayMetrics)

    fun text(context: Context, style: Int, value: CharSequence? = null): TextView = TextView(context).apply {
        setTextAppearance(style)
        if (value != null) text = value
    }

    fun column(context: Context, gapDp: Int = 0): LinearLayout = LinearLayout(context).apply {
        orientation = LinearLayout.VERTICAL
        if (gapDp > 0) {
            showDividers = LinearLayout.SHOW_DIVIDER_MIDDLE
            // Прозрачный разделитель — отступ между элементами без лишних View.
            dividerDrawable = GradientDrawable().apply { setSize(dp(context, gapDp), dp(context, gapDp)) }
        }
    }

    fun row(context: Context, gapDp: Int = 0): LinearLayout = LinearLayout(context).apply {
        orientation = LinearLayout.HORIZONTAL
        gravity = Gravity.CENTER_VERTICAL
        if (gapDp > 0) {
            showDividers = LinearLayout.SHOW_DIVIDER_MIDDLE
            dividerDrawable = GradientDrawable().apply { setSize(dp(context, gapDp), dp(context, gapDp)) }
        }
    }

    /** Карточка: поверхность с обводкой и внутренним отступом 16 dp. */
    fun card(context: Context, gapDp: Int = 8): LinearLayout = column(context, gapDp).apply {
        setBackgroundResource(R.drawable.bg_card)
        val p = dp(context, 16)
        setPadding(p, p, p, p)
    }

    /** Карточка-список: строки внутри без своего отступа, разделены тонкой линией. */
    fun listCard(context: Context): LinearLayout = LinearLayout(context).apply {
        orientation = LinearLayout.VERTICAL
        setBackgroundResource(R.drawable.bg_card)
        val p = dp(context, 4)
        setPadding(0, p, 0, p)
        clipToOutline = true
    }

    enum class Style { PRIMARY, TONAL, OUTLINE, TEXT }

    fun button(context: Context, label: Int, style: Style, icon: Int? = null): Button = Button(context).apply {
        setText(label)
        isAllCaps = false
        stateListAnimator = null
        setTextAppearance(R.style.Text_DPpass_Label)
        val (bg, fg) = when (style) {
            Style.PRIMARY -> R.drawable.bg_button_primary to R.color.on_primary
            Style.TONAL -> R.drawable.bg_button_tonal to R.color.on_primary_container
            Style.OUTLINE -> R.drawable.bg_button_outline to R.color.primary
            Style.TEXT -> R.drawable.bg_row to R.color.primary
        }
        setBackgroundResource(bg)
        setTextColor(context.getColor(fg))
        minHeight = dp(context, TOUCH_DP)
        minimumHeight = dp(context, TOUCH_DP)
        minWidth = dp(context, TOUCH_DP)
        minimumWidth = dp(context, TOUCH_DP)
        setPadding(dp(context, if (style == Style.TEXT) 12 else 20), 0, dp(context, if (style == Style.TEXT) 12 else 20), 0)
        if (icon != null) {
            setCompoundDrawablesWithIntrinsicBounds(icon, 0, 0, 0)
            compoundDrawablePadding = dp(context, 8)
            compoundDrawableTintList = ColorStateList.valueOf(context.getColor(fg))
        }
    }

    fun icon(context: Context, res: Int, tint: Int, sizeDp: Int = 24): ImageView = ImageView(context).apply {
        setImageResource(res)
        imageTintList = ColorStateList.valueOf(context.getColor(tint))
        layoutParams = LinearLayout.LayoutParams(dp(context, sizeDp), dp(context, sizeDp))
        // Значок рядом с текстом — украшение: TalkBack читает текст.
        importantForAccessibility = View.IMPORTANT_FOR_ACCESSIBILITY_NO
    }

    /** Кнопка-значок 48 dp с подписью для TalkBack. */
    fun iconButton(context: Context, res: Int, description: CharSequence, tint: Int = R.color.text, onClick: () -> Unit): FrameLayout =
        FrameLayout(context).apply {
            foreground = context.getDrawable(R.drawable.fg_ripple_oval)
            isClickable = true
            isFocusable = true
            contentDescription = description
            setOnClickListener { onClick() }
            addView(
                ImageView(context).apply {
                    setImageResource(res)
                    imageTintList = ColorStateList.valueOf(context.getColor(tint))
                    importantForAccessibility = View.IMPORTANT_FOR_ACCESSIBILITY_NO
                },
                FrameLayout.LayoutParams(dp(context, 24), dp(context, 24), Gravity.CENTER),
            )
            layoutParams = LinearLayout.LayoutParams(dp(context, TOUCH_DP), dp(context, TOUCH_DP))
        }

    /** Плашка состояния: цвет фона и текста — пара токенов. */
    fun chip(context: Context, value: CharSequence, background: Int, foreground: Int): TextView =
        text(context, R.style.Text_DPpass_Caption, value).apply {
            setBackgroundResource(R.drawable.bg_pill)
            backgroundTintList = ColorStateList.valueOf(context.getColor(background))
            setTextColor(context.getColor(foreground))
            setPadding(dp(context, 10), dp(context, 4), dp(context, 10), dp(context, 4))
            maxLines = 1
            ellipsize = TextUtils.TruncateAt.END
        }

    /** Кружок с флагом или буквой (`Avatar`). */
    fun avatar(context: Context, value: String, sizeDp: Int = 40): TextView = TextView(context).apply {
        text = value
        gravity = Gravity.CENTER
        setBackgroundResource(R.drawable.bg_oval)
        // Флаг — эмодзи: крупнее буквы. Размер — в dp, а не в sp: буква и флаг здесь значок
        // в круге постоянного размера, при крупном шрифте системы они обрезались бы; имя
        // сервера рядом растёт со шрифтом.
        val emoji = value.codePointCount(0, value.length) > 1 || value.codePointAt(0) > 0xFFFF
        setTextAppearance(R.style.Text_DPpass_Title)
        setTextSize(TypedValue.COMPLEX_UNIT_DIP, if (emoji) 20f else 16f)
        setTextColor(context.getColor(R.color.on_primary_container))
        backgroundTintList = ColorStateList.valueOf(context.getColor(R.color.primary_container))
        importantForAccessibility = View.IMPORTANT_FOR_ACCESSIBILITY_NO
        layoutParams = LinearLayout.LayoutParams(dp(context, sizeDp), dp(context, sizeDp))
    }

    /** Кружок со значком (вместо буквы): «Автоматически», свои серверы. */
    fun iconAvatar(context: Context, res: Int, sizeDp: Int = 40): FrameLayout = FrameLayout(context).apply {
        setBackgroundResource(R.drawable.bg_oval)
        backgroundTintList = ColorStateList.valueOf(context.getColor(R.color.primary_container))
        importantForAccessibility = View.IMPORTANT_FOR_ACCESSIBILITY_NO
        addView(
            ImageView(context).apply {
                setImageResource(res)
                imageTintList = ColorStateList.valueOf(context.getColor(R.color.on_primary_container))
            },
            FrameLayout.LayoutParams(dp(context, 22), dp(context, 22), Gravity.CENTER),
        )
        layoutParams = LinearLayout.LayoutParams(dp(context, sizeDp), dp(context, sizeDp))
    }

    /** Заголовок раздела над карточкой. */
    fun section(context: Context, title: CharSequence): TextView = text(context, R.style.Text_DPpass_Section, title).apply {
        setPadding(dp(context, 4), dp(context, 8), dp(context, 4), 0)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) isAccessibilityHeading = true
    }

    /**
     * Строка списка: значок, заголовок с подписью и справа — что угодно
     * (переключатель, текст, стрелка). Касаемая область — вся строка.
     */
    // Строка создаётся только из кода экранов (D-34): конструктора для разметки XML ей не нужно.
    @SuppressLint("ViewConstructor")
    class ListRow(context: Context, iconRes: Int?, title: CharSequence) : LinearLayout(context) {
        val title: TextView = text(context, R.style.Text_DPpass_Body, title)
        val subtitle: TextView = text(context, R.style.Text_DPpass_Caption).apply { visibility = View.GONE }
        val icon: ImageView? = iconRes?.let { icon(context, it, R.color.text_secondary) }
        private val trailing = FrameLayout(context)

        init {
            orientation = HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
            minimumHeight = dp(context, 56)
            val h = dp(context, 16)
            setPadding(h, dp(context, 8), dp(context, 12), dp(context, 8))
            icon?.let { addView(it, LayoutParams(dp(context, 24), dp(context, 24)).apply { marginEnd = dp(context, 16) }) }
            val texts = column(context, 2)
            texts.addView(this.title)
            texts.addView(subtitle)
            addView(texts, weight())
            addView(trailing, LayoutParams(LayoutParams.WRAP_CONTENT, LayoutParams.WRAP_CONTENT).apply { marginStart = dp(context, 8) })
        }

        fun subtitle(value: CharSequence?): ListRow = apply {
            subtitle.text = value
            subtitle.visibility = if (value.isNullOrEmpty()) View.GONE else View.VISIBLE
        }

        fun trailing(view: View?): ListRow = apply {
            trailing.removeAllViews()
            if (view != null) trailing.addView(view)
        }

        fun onClick(action: () -> Unit): ListRow = apply {
            setBackgroundResource(R.drawable.bg_row)
            isClickable = true
            isFocusable = true
            setOnClickListener { action() }
        }
    }

    /**
     * Строка с переключателем: касание строки переключает; TalkBack читает её
     * как переключатель. Бегунок выключенного — `outline_strong`, а не цвет
     * поверхности: иначе он сливается с карточкой (WCAG 1.4.11).
     */
    fun switchRow(context: Context, iconRes: Int?, title: CharSequence, subtitle: CharSequence?, checked: Boolean, onChange: (Boolean) -> Unit): ListRow {
        val toggle = Switch(context).apply {
            isChecked = checked
            isClickable = false
            isFocusable = false
            importantForAccessibility = View.IMPORTANT_FOR_ACCESSIBILITY_NO
            thumbTintList = ColorStateList(
                arrayOf(intArrayOf(android.R.attr.state_checked), intArrayOf()),
                intArrayOf(context.getColor(R.color.primary), context.getColor(R.color.outline_strong)),
            )
            trackTintList = ColorStateList(
                arrayOf(intArrayOf(android.R.attr.state_checked), intArrayOf()),
                intArrayOf(context.getColor(R.color.primary_container), context.getColor(R.color.outline)),
            )
        }
        return ListRow(context, iconRes, title).subtitle(subtitle).trailing(toggle).apply {
            setBackgroundResource(R.drawable.bg_row)
            isClickable = true
            isFocusable = true
            accessibilityDelegate = object : View.AccessibilityDelegate() {
                override fun onInitializeAccessibilityNodeInfo(host: View, info: AccessibilityNodeInfo) {
                    super.onInitializeAccessibilityNodeInfo(host, info)
                    info.className = Switch::class.java.name
                    info.isCheckable = true
                    checkedState(info, toggle.isChecked)
                }

                // Событие касания — с новым состоянием: TalkBack произносит «включено» или «выключено».
                override fun onInitializeAccessibilityEvent(host: View, event: AccessibilityEvent) {
                    super.onInitializeAccessibilityEvent(host, event)
                    event.className = Switch::class.java.name
                    event.isChecked = toggle.isChecked
                }
            }
            setOnClickListener {
                toggle.isChecked = !toggle.isChecked
                onChange(toggle.isChecked)
            }
        }
    }

    /**
     * Отмечен ли флажок или переключатель — для TalkBack. С Android 16 —
     * `setChecked(int)` (есть и «частично»), `setChecked(boolean)` устарел;
     * раньше — только он.
     */
    fun checkedState(info: AccessibilityNodeInfo, checked: Boolean) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.BAKLAVA) {
            info.setChecked(if (checked) AccessibilityNodeInfo.CHECKED_STATE_TRUE else AccessibilityNodeInfo.CHECKED_STATE_FALSE)
        } else {
            // Замена — ветка выше, её нет до Android 16.
            @Suppress("DEPRECATION")
            info.isChecked = checked
        }
    }

    /** Строка выбора одного из нескольких (радиокнопка слева). */
    fun radioRow(context: Context, title: CharSequence, subtitle: CharSequence?, selected: Boolean, onClick: () -> Unit): ListRow =
        ListRow(context, if (selected) R.drawable.ic_radio_on else R.drawable.ic_radio_off, title).subtitle(subtitle).onClick(onClick).apply {
            icon?.imageTintList = ColorStateList.valueOf(context.getColor(if (selected) R.color.primary else R.color.text_secondary))
            isSelected = selected
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) stateDescription = if (selected) context.getString(R.string.a11y_selected) else null
        }

    /** Тонкий разделитель внутри карточки-списка, с отступом под значок. */
    fun divider(context: Context, insetDp: Int = 56): View = View(context).apply {
        setBackgroundColor(context.getColor(R.color.outline))
        layoutParams = LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, maxOf(1, dp(context, 1) / 2)).apply {
            marginStart = dp(context, insetDp)
        }
        importantForAccessibility = View.IMPORTANT_FOR_ACCESSIBILITY_NO
    }

    /**
     * Сегменты: выбор одного из 2–3 вариантов в одну строку (режим
     * маршрутизации, порядок серверов). Касаемая область сегмента — 48 dp
     * по высоте, видимая плашка — 40 dp: отступ сверху и снизу — у рисунка
     * (`bg_segment`, `fg_ripple_segment`), а не у дорожки, иначе касание у
     * края дорожки не попадает в сегмент. У выбранного — линия снизу внутри
     * плашки (WCAG 1.4.11); отступ текста 10 dp сверху и снизу держит её под
     * текстом и при двух строках и крупном шрифте, а одна строка стоит там же,
     * где без линии.
     */
    fun segmented(context: Context, options: List<CharSequence>, selected: Int, onSelect: (Int) -> Unit): LinearLayout =
        LinearLayout(context).apply {
            orientation = LinearLayout.HORIZONTAL
            setBackgroundResource(R.drawable.bg_pill)
            backgroundTintList = ColorStateList.valueOf(context.getColor(R.color.surface_variant))
            setPadding(dp(context, 4), 0, dp(context, 4), 0)
            options.forEachIndexed { i, label ->
                val on = i == selected
                addView(
                    text(context, R.style.Text_DPpass_Label, label).apply {
                        gravity = Gravity.CENTER
                        minHeight = dp(context, TOUCH_DP)
                        maxLines = 2
                        if (on) {
                            setBackgroundResource(R.drawable.bg_segment)
                            elevation = dpF(context, 1f)
                        } else {
                            foreground = context.getDrawable(R.drawable.fg_ripple_segment)
                        }
                        // После фона: отступы рисунка заменили бы заданные раньше.
                        setPadding(dp(context, 12), dp(context, 10), dp(context, 12), dp(context, 10))
                        setTextColor(context.getColor(if (on) R.color.text else R.color.text_secondary))
                        isClickable = true
                        isFocusable = true
                        isSelected = on
                        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) stateDescription = if (on) context.getString(R.string.a11y_selected) else null
                        setOnClickListener { if (!on) onSelect(i) }
                    },
                    LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f),
                )
            }
        }

    /** Поле поиска: значок, текст, линия снизу (`bg_field`). [onChange] — на каждый ввод. */
    fun searchField(context: Context, hint: Int, onChange: (String) -> Unit): EditText = EditText(context).apply {
        setHint(hint)
        setTextAppearance(R.style.Text_DPpass_Body)
        setHintTextColor(context.getColor(R.color.text_secondary))
        setBackgroundResource(R.drawable.bg_field)
        inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS
        isSingleLine = true
        minHeight = dp(context, TOUCH_DP)
        setPadding(dp(context, 12), 0, dp(context, 12), 0)
        setCompoundDrawablesWithIntrinsicBounds(R.drawable.ic_search, 0, 0, 0)
        compoundDrawablePadding = dp(context, 8)
        compoundDrawableTintList = ColorStateList.valueOf(context.getColor(R.color.text_secondary))
        addTextChangedListener(object : TextWatcher {
            override fun beforeTextChanged(s: CharSequence?, start: Int, count: Int, after: Int) = Unit
            override fun onTextChanged(s: CharSequence?, start: Int, before: Int, count: Int) = Unit
            override fun afterTextChanged(s: Editable?) {
                onChange(s?.toString().orEmpty())
            }
        })
    }

    /** Поле ввода формы (адрес подписки, имя): линия снизу, в фокусе — толще и цвета primary (`bg_field`). */
    fun field(context: Context, hint: Int, type: Int = InputType.TYPE_CLASS_TEXT): EditText = EditText(context).apply {
        setHint(hint)
        setTextAppearance(R.style.Text_DPpass_Body)
        setHintTextColor(context.getColor(R.color.text_secondary))
        setBackgroundResource(R.drawable.bg_field)
        inputType = type
        isSingleLine = true
        minHeight = dp(context, 52)
        setPadding(dp(context, 16), 0, dp(context, 16), 0)
    }

    /**
     * Шкала: доля от 0 до 1 (трафик подписки). Цвет — по доле: больше 90 % —
     * предупреждение.
     */
    class Meter(context: Context) : View(context) {
        private val track = Paint(Paint.ANTI_ALIAS_FLAG).apply { color = context.getColor(R.color.surface_variant) }
        private val fill = Paint(Paint.ANTI_ALIAS_FLAG).apply { color = context.getColor(R.color.primary) }
        private val rect = RectF()
        var fraction: Float = 0f
            set(value) {
                field = value.coerceIn(0f, 1f)
                fill.color = context.getColor(if (field >= 0.9f) R.color.warning else R.color.primary)
                invalidate()
            }

        init {
            importantForAccessibility = IMPORTANT_FOR_ACCESSIBILITY_NO
        }

        override fun onMeasure(widthMeasureSpec: Int, heightMeasureSpec: Int) {
            setMeasuredDimension(MeasureSpec.getSize(widthMeasureSpec), dp(context, 8))
        }

        override fun onDraw(canvas: Canvas) {
            val r = height / 2f
            rect.set(0f, 0f, width.toFloat(), height.toFloat())
            canvas.drawRoundRect(rect, r, r, track)
            if (fraction > 0f) {
                rect.set(0f, 0f, maxOf(height.toFloat(), width * fraction), height.toFloat())
                canvas.drawRoundRect(rect, r, r, fill)
            }
        }
    }

    /**
     * Нижний лист: диалог у нижнего края со скруглённым верхом — меню
     * подписки, выбор, сводка импорта. Снимки экрана запрещены и здесь (T9).
     */
    fun sheet(activity: Activity, title: CharSequence?, content: View): Dialog {
        val dialog = Dialog(activity)
        dialog.requestWindowFeature(Window.FEATURE_NO_TITLE)
        val body = column(activity, 0).apply {
            setBackgroundResource(R.drawable.bg_sheet)
            val side = dp(activity, 16)
            setPadding(side, dp(activity, 12), side, dp(activity, 16))
            addView(
                View(activity).apply { setBackgroundResource(R.drawable.bg_handle) },
                LinearLayout.LayoutParams(dp(activity, 36), dp(activity, 4)).apply {
                    gravity = Gravity.CENTER_HORIZONTAL
                    bottomMargin = dp(activity, 12)
                },
            )
            if (title != null) {
                addView(
                    text(activity, R.style.Text_DPpass_Title, title).apply {
                        setPadding(dp(activity, 4), 0, dp(activity, 4), dp(activity, 8))
                        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) isAccessibilityHeading = true
                    },
                )
            }
            addView(ScrollView(activity).apply { addView(content) }, matchWidth())
        }
        dialog.setContentView(body)
        dialog.window?.let { w ->
            w.setBackgroundDrawable(ColorDrawable(Color.TRANSPARENT))
            w.setGravity(Gravity.BOTTOM)
            w.setLayout(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT)
            w.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)
            w.setWindowAnimations(android.R.style.Animation_InputMethod)
        }
        return dialog
    }

    /**
     * Запретить снимки и запись окна диалога (T9, D-47): у `AlertDialog` своё
     * окно, и `FLAG_SECURE` активности его не закрывает — ставим на нём.
     * Возвращает тот же диалог для цепочки.
     */
    fun <T : Dialog> secure(dialog: T): T {
        dialog.window?.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)
        if (dialog is AlertDialog) {
            dialog.getButton(AlertDialog.BUTTON_POSITIVE)?.filterTouchesWhenObscured = true
        }
        return dialog
    }

    /**
     * В буфер обмена (раздача D-51, прокси без VPN D-95); логин и пароль — с
     * пометкой «чувствительное»: Android 13+ не показывает их в предпросмотре.
     * Ложь — буфер недоступен. До Android 13 о скопированном сообщает сам
     * вызывающий: система — только с 13.
     */
    fun copy(context: Context, label: CharSequence, text: String, sensitive: Boolean): Boolean {
        val clip = ClipData.newPlainText(label, text)
        if (sensitive && Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            clip.description.extras = PersistableBundle().apply { putBoolean(ClipDescription.EXTRA_IS_SENSITIVE, true) }
        }
        return runCatching { context.getSystemService(ClipboardManager::class.java).setPrimaryClip(clip) }.isSuccess
    }

    fun matchWidth(): LinearLayout.LayoutParams =
        LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT)

    fun wrap(): LinearLayout.LayoutParams =
        LinearLayout.LayoutParams(ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT)

    fun weight(): LinearLayout.LayoutParams = LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f)

    /** Значок задержки (D-41): цвет — уровень, текст — миллисекунды или что случилось. */
    fun latencyChip(context: Context, label: LatencyLabel): TextView? {
        val (text, bg, fg) = when (label.level) {
            LatencyLevel.UNKNOWN -> return null
            LatencyLevel.GOOD -> Triple(context.getString(R.string.latency_ms, label.millis), R.color.success_container, R.color.success)
            LatencyLevel.FAIR -> Triple(context.getString(R.string.latency_ms, label.millis), R.color.warning_container, R.color.warning)
            LatencyLevel.POOR -> Triple(context.getString(R.string.latency_ms, label.millis), R.color.error_container, R.color.error)
            LatencyLevel.FAILED -> Triple(context.getString(R.string.latency_failed), R.color.error_container, R.color.error)
            LatencyLevel.UDP -> Triple(context.getString(R.string.latency_udp), R.color.surface_variant, R.color.text_secondary)
        }
        return chip(context, text, bg, fg)
    }

    /** Заголовок отказа по категории (D-22): подробность — в сообщении диагностики. */
    fun kind(kind: FailureKind): Int = when (kind) {
        FailureKind.NETWORK_UNREACHABLE -> R.string.kind_network_unreachable
        FailureKind.DNS_RESOLUTION_FAILED -> R.string.kind_dns_resolution_failed
        FailureKind.CONFIG_PARSE_FAILED -> R.string.kind_config_parse_failed
        FailureKind.CONFIG_FORMAT_UNSUPPORTED -> R.string.kind_config_format_unsupported
        FailureKind.CONFIG_VALIDATION_FAILED -> R.string.kind_config_validation_failed
        FailureKind.CAPABILITY_UNSUPPORTED -> R.string.kind_capability_unsupported
        FailureKind.ROUTE_COMPILATION_FAILED -> R.string.kind_route_compilation_failed
        FailureKind.BACKEND_VALIDATION_FAILED -> R.string.kind_backend_validation_failed
        FailureKind.BACKEND_START_FAILED -> R.string.kind_backend_start_failed
        FailureKind.TUN_START_FAILED -> R.string.kind_tun_start_failed
        FailureKind.ENDPOINT_UNREACHABLE -> R.string.kind_endpoint_unreachable
        FailureKind.TLS_HANDSHAKE_FAILED -> R.string.kind_tls_handshake_failed
        FailureKind.AUTHENTICATION_FAILED -> R.string.kind_authentication_failed
        FailureKind.HEALTH_CHECK_FAILED -> R.string.kind_health_check_failed
        FailureKind.SUBSCRIPTION_FETCH_FAILED -> R.string.kind_subscription_fetch_failed
        FailureKind.SUBSCRIPTION_INVALID -> R.string.kind_subscription_invalid
        FailureKind.STORAGE_FAILED -> R.string.kind_storage_failed
        FailureKind.INTERNAL -> R.string.kind_internal
    }
}
