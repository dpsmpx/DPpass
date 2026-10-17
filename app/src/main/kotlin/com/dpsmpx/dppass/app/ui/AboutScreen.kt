package com.dpsmpx.dppass.app.ui

import android.content.ActivityNotFoundException
import android.content.Intent
import android.net.Uri
import android.view.Gravity
import android.view.View
import android.widget.ImageView
import android.widget.LinearLayout
import com.dpsmpx.dppass.R
import com.dpsmpx.dppass.app.TunnelStatus
import com.dpsmpx.dppass.engine.xray.XrayBackend
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.IOException

/**
 * «О программе» (D-43): версия приложения и ядра, из чего собран набор
 * геоданных, атрибуция DB-IP (условие CC BY 4.0), что DPpass не собирает
 * (D-12), и уведомления о сторонних компонентах.
 */
class AboutScreen(host: Host) : SubScreen(host, R.string.about_title) {
    override fun content(): View = Ui.column(context, 12).apply {
        addView(
            Ui.card(context, 8).apply {
                gravity = Gravity.CENTER_HORIZONTAL
                addView(
                    ImageView(context).apply {
                        setImageResource(R.mipmap.ic_launcher)
                        importantForAccessibility = View.IMPORTANT_FOR_ACCESSIBILITY_NO
                    },
                    LinearLayout.LayoutParams(Ui.dp(context, 72), Ui.dp(context, 72)).apply { gravity = Gravity.CENTER_HORIZONTAL },
                )
                addView(
                    Ui.text(context, R.style.Text_DPpass_Headline, context.getString(R.string.app_name)).apply { gravity = Gravity.CENTER_HORIZONTAL },
                    Ui.matchWidth(),
                )
                addView(
                    Ui.text(context, R.style.Text_DPpass_Secondary, context.getString(R.string.about_version, host.graph?.appVersion ?: "?")).apply {
                        gravity = Gravity.CENTER_HORIZONTAL
                    },
                    Ui.matchWidth(),
                )
                addView(
                    Ui.text(context, R.style.Text_DPpass_Caption, context.getString(R.string.about_not_release)).apply {
                        gravity = Gravity.CENTER_HORIZONTAL
                    },
                    Ui.matchWidth(),
                )
            },
            Ui.matchWidth(),
        )
        addView(
            Ui.listCard(context).apply {
                addView(
                    Ui.ListRow(context, R.drawable.ic_shield, context.getString(R.string.about_engine)).subtitle("Xray-core ${XrayBackend.VERSION} · MPL-2.0"),
                    Ui.matchWidth(),
                )
                addView(Ui.divider(context))
                addView(Ui.ListRow(context, R.drawable.ic_dns, context.getString(R.string.about_geodata)).subtitle(host.graph?.geodata ?: "—"), Ui.matchWidth())
                addView(Ui.divider(context))
                addView(
                    Ui.ListRow(context, R.drawable.ic_open, context.getString(R.string.about_dbip))
                        .subtitle("https://db-ip.com")
                        .onClick { open("https://db-ip.com") },
                    Ui.matchWidth(),
                )
                addView(Ui.divider(context))
                addView(
                    Ui.ListRow(context, R.drawable.ic_file, context.getString(R.string.about_licenses))
                        .subtitle(context.getString(R.string.about_licenses_note))
                        .trailing(Ui.icon(context, R.drawable.ic_chevron, R.color.text_secondary))
                        .onClick { host.push(LicensesScreen(host)) },
                    Ui.matchWidth(),
                )
            },
            Ui.matchWidth(),
        )
        addView(Ui.section(context, context.getString(R.string.about_privacy)))
        addView(
            Ui.card(context).apply { addView(Ui.text(context, R.style.Text_DPpass_Secondary, context.getString(R.string.about_privacy_text))) },
            Ui.matchWidth(),
        )
    }

    override fun render(status: TunnelStatus) = Unit

    private fun open(url: String) {
        try {
            context.startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(url)).addCategory(Intent.CATEGORY_BROWSABLE))
        } catch (e: ActivityNotFoundException) {
            host.toast(context.getString(R.string.no_browser))
        }
    }
}

/**
 * Уведомления о сторонних компонентах (D-43): `assets/notices/NOTICES.txt`
 * (собирает `tools/legal/notices.py` из матрицы лицензий) и уведомления
 * набора геоданных `assets/geodata/NOTICE.txt` (D-27). Текст длинный —
 * читается в фоне и показывается частями.
 */
class LicensesScreen(host: Host) : SubScreen(host, R.string.about_licenses) {
    private val body = Ui.column(context, 12)
    private var loaded = false

    override fun content(): View = body.apply {
        addView(Ui.text(context, R.style.Text_DPpass_Secondary, context.getString(R.string.apps_loading)))
    }

    override fun render(status: TunnelStatus) = Unit

    override fun onShown() {
        if (loaded) return
        loaded = true
        host.scope.launch {
            val parts = withContext(Dispatchers.IO) {
                listOf("notices/NOTICES.txt", "geodata/NOTICE.txt").flatMap { name ->
                    val text = try {
                        context.assets.open(name).use { String(it.readBytes(), Charsets.UTF_8) }
                    } catch (e: IOException) {
                        context.getString(R.string.about_notice_missing, name)
                    }
                    // Частями по текстам лицензий: один огромный TextView раскладывается медленно.
                    text.split(Regex("(?m)^(?=--- \\[)")).filter { it.isNotBlank() }
                }
            }
            body.removeAllViews()
            for (p in parts) {
                body.addView(
                    Ui.card(context).apply { addView(Ui.text(context, R.style.Text_DPpass_Mono, p.trim()).apply { setTextIsSelectable(true) }) },
                    Ui.matchWidth(),
                )
            }
        }
    }
}
