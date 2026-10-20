package com.dpsmpx.dppass.app.ui

import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.graphics.drawable.Drawable
import android.os.Build
import android.text.TextUtils
import android.view.View
import android.view.accessibility.AccessibilityEvent
import android.view.accessibility.AccessibilityNodeInfo
import android.widget.CheckBox
import android.widget.ImageView
import android.widget.LinearLayout
import com.dpsmpx.dppass.R
import com.dpsmpx.dppass.app.TunnelStatus
import com.dpsmpx.dppass.connection.AppMode
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/** Приложение в списке раздельного туннелирования. */
data class AppEntry(val packageName: String, val label: String, val icon: Drawable?)

/**
 * Раздельное туннелирование (D-38): все приложения; все, кроме
 * выбранных; только выбранные. Список — приложения с ярлыком запуска
 * (`<queries>`), без `QUERY_ALL_PACKAGES`; сам DPpass в туннель не
 * входит никогда (D-17). Выбор применяется кнопкой «Готово» одним
 * вызовом [apply]: сменой политики или, без сервера (D-73), своим выбором
 * режима.
 */
class AppsScreen(
    host: Host,
    title: Int,
    initialMode: AppMode,
    initialApps: Set<String>,
    private val apply: (AppMode, Set<String>) -> Unit,
) : SubScreen(host, title) {
    private var mode: AppMode = initialMode
    private val chosen = LinkedHashSet(initialApps)
    private var apps: List<AppEntry> = emptyList()
    private var query = ""
    private val modes = LinearLayout(context)
    private val list = Ui.listCard(context)
    private val hint = Ui.text(context, R.style.Text_DPpass_Caption)
    private val loading = Ui.text(context, R.style.Text_DPpass_Secondary, context.getString(R.string.apps_loading))
    private val search = Ui.searchField(context, R.string.apps_search) {
        query = it
        renderList()
    }

    override fun content(): View = Ui.column(context, 12).apply {
        addView(modes, Ui.matchWidth())
        addView(hint.apply { setPadding(Ui.dp(context, 4), 0, Ui.dp(context, 4), 0) })
        addView(search, Ui.matchWidth())
        addView(loading)
        addView(list, Ui.matchWidth())
        addView(
            Ui.button(context, R.string.action_done, Ui.Style.PRIMARY, R.drawable.ic_check).apply {
                setOnClickListener {
                    if (mode == AppMode.ONLY && chosen.isEmpty()) {
                        host.toast(context.getString(R.string.apps_only_empty))
                        return@setOnClickListener
                    }
                    apply(mode, chosen.toSet())
                    host.pop()
                }
            },
            Ui.matchWidth(),
        )
    }

    override fun render(status: TunnelStatus) {
        modes.removeAllViews()
        modes.addView(
            Ui.segmented(
                context,
                listOf(context.getString(R.string.apps_mode_all), context.getString(R.string.apps_mode_except), context.getString(R.string.apps_mode_only)),
                mode.ordinal,
            ) {
                mode = AppMode.entries[it]
                render(status)
            },
            Ui.matchWidth(),
        )
        hint.setText(
            when (mode) {
                AppMode.ALL -> R.string.apps_mode_all_note
                AppMode.EXCEPT -> R.string.apps_mode_except_note
                AppMode.ONLY -> R.string.apps_mode_only_note
            },
        )
        renderList()
    }

    override fun onShown() {
        if (apps.isNotEmpty()) return
        host.scope.launch {
            apps = withContext(Dispatchers.IO) { launcherApps() }
            loading.visibility = View.GONE
            renderList()
        }
    }

    private fun renderList() {
        val visible = mode != AppMode.ALL
        search.visibility = if (visible && apps.size > 8) View.VISIBLE else View.GONE
        list.visibility = if (visible && apps.isNotEmpty()) View.VISIBLE else View.GONE
        if (!visible) return
        list.removeAllViews()
        val q = query.trim().lowercase()
        // Выбранные — наверху: их проще проверить.
        val shown = apps.filter { q.isEmpty() || q in it.label.lowercase() || q in it.packageName }
            .sortedWith(compareBy({ it.packageName !in chosen }, { it.label.lowercase() }))
        shown.forEachIndexed { i, app ->
            if (i > 0) list.addView(Ui.divider(context, 64))
            list.addView(row(app), Ui.matchWidth())
        }
    }

    private fun row(app: AppEntry): View {
        val check = CheckBox(context).apply {
            isChecked = app.packageName in chosen
            isClickable = false
            isFocusable = false
            importantForAccessibility = View.IMPORTANT_FOR_ACCESSIBILITY_NO
            buttonTintList = android.content.res.ColorStateList.valueOf(context.getColor(R.color.primary))
        }
        return Ui.row(context).apply {
            setBackgroundResource(R.drawable.bg_row)
            setPadding(Ui.dp(context, 16), Ui.dp(context, 8), Ui.dp(context, 8), Ui.dp(context, 8))
            minimumHeight = Ui.dp(context, 56)
            isClickable = true
            isFocusable = true
            addView(
                ImageView(context).apply {
                    setImageDrawable(app.icon)
                    importantForAccessibility = View.IMPORTANT_FOR_ACCESSIBILITY_NO
                },
                LinearLayout.LayoutParams(Ui.dp(context, 36), Ui.dp(context, 36)),
            )
            val texts = Ui.column(context, 2)
            texts.addView(
                Ui.text(context, R.style.Text_DPpass_Body, app.label).apply {
                    maxLines = 1
                    ellipsize = TextUtils.TruncateAt.END
                },
            )
            texts.addView(
                Ui.text(context, R.style.Text_DPpass_Caption, app.packageName).apply {
                    maxLines = 1
                    ellipsize = TextUtils.TruncateAt.MIDDLE
                },
            )
            addView(texts, Ui.weight().apply { marginStart = Ui.dp(context, 12) })
            addView(check)
            contentDescription = app.label
            // Строка — флажок для TalkBack на всех версиях Android (stateDescription — только с 11-й),
            // как строка с переключателем (Ui.switchRow); событие касания несёт новое состояние.
            accessibilityDelegate = object : View.AccessibilityDelegate() {
                override fun onInitializeAccessibilityNodeInfo(host: View, info: AccessibilityNodeInfo) {
                    super.onInitializeAccessibilityNodeInfo(host, info)
                    info.className = CheckBox::class.java.name
                    info.isCheckable = true
                    Ui.checkedState(info, check.isChecked)
                }

                override fun onInitializeAccessibilityEvent(host: View, event: AccessibilityEvent) {
                    super.onInitializeAccessibilityEvent(host, event)
                    event.className = CheckBox::class.java.name
                    event.isChecked = check.isChecked
                }
            }
            setOnClickListener {
                if (!chosen.add(app.packageName)) chosen.remove(app.packageName)
                check.isChecked = app.packageName in chosen
            }
        }
    }

    private fun launcherApps(): List<AppEntry> = launcherApps(context)
}

/** Приложения с ярлыком запуска, кроме самого DPpass, — по алфавиту (выбор приложений, «Почему этот маршрут»). */
internal fun launcherApps(context: Context): List<AppEntry> {
    val pm = context.packageManager
    val intent = Intent(Intent.ACTION_MAIN).addCategory(Intent.CATEGORY_LAUNCHER)
    val found = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
        pm.queryIntentActivities(intent, PackageManager.ResolveInfoFlags.of(0))
    } else {
        @Suppress("DEPRECATION") // замена — ResolveInfoFlags, только с API 33
        pm.queryIntentActivities(intent, 0)
    }
    return found
        .map { it.activityInfo.applicationInfo }
        .distinctBy { it.packageName }
        .filter { it.packageName != context.packageName }
        .map { AppEntry(it.packageName, pm.getApplicationLabel(it).toString(), runCatching { pm.getApplicationIcon(it) }.getOrNull()) }
        .sortedBy { it.label.lowercase() }
}
