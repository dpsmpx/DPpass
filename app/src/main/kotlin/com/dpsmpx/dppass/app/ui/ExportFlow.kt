package com.dpsmpx.dppass.app.ui

import android.app.AlertDialog
import android.app.Dialog
import android.content.Intent
import com.dpsmpx.dppass.R
import com.dpsmpx.dppass.config.ConfigWriter

/**
 * Экспорт активной конфигурации (D-11): документ DPpass текущего формата.
 * По умолчанию — без секретов: идентификаторы и пароли заменены меткой,
 * такой документ можно показать или отправить, но не активировать. С
 * секретами — только в файл и только после предупреждения: такой документ
 * открывает серверы любому, у кого он окажется.
 */
internal object ExportFlow {
    const val FILE_REDACTED: String = "dppass-config.json"
    const val FILE_FULL: String = "dppass-config-full.json"

    fun menu(host: Host) {
        val c = host.activity
        val core = host.graph?.core ?: return host.toast(c.getString(R.string.not_ready))
        if (core.export() == null) return host.toast(c.getString(R.string.export_none))
        lateinit var sheet: Dialog
        val body = Ui.column(c, 12).apply {
            addView(Ui.text(c, R.style.Text_DPpass_Body, c.getString(R.string.export_note)))
            addView(
                Ui.button(c, R.string.export_save, Ui.Style.PRIMARY, R.drawable.ic_file).apply {
                    setOnClickListener {
                        sheet.dismiss()
                        core.export()?.let { host.saveDocument(FILE_REDACTED, it) }
                    }
                },
                Ui.matchWidth(),
            )
            addView(
                Ui.button(c, R.string.export_share, Ui.Style.TONAL, R.drawable.ic_open).apply {
                    setOnClickListener {
                        sheet.dismiss()
                        core.export()?.let { share(host, it) }
                    }
                },
                Ui.matchWidth(),
            )
            addView(
                Ui.button(c, R.string.export_full, Ui.Style.TEXT, R.drawable.ic_key).apply {
                    setOnClickListener {
                        sheet.dismiss()
                        confirmFull(host)
                    }
                },
                Ui.matchWidth(),
            )
        }
        sheet = Ui.sheet(c, c.getString(R.string.export_title), body)
        sheet.show()
    }

    /** Без секретов — и в другие приложения: метка вместо секрета, активировать нельзя. */
    private fun share(host: Host, text: String) {
        val send = Intent(Intent.ACTION_SEND).setType("text/plain").putExtra(Intent.EXTRA_TEXT, text)
        try {
            host.activity.startActivity(Intent.createChooser(send, host.activity.getString(R.string.export_share)))
        } catch (e: android.content.ActivityNotFoundException) {
            host.toast(host.activity.getString(R.string.no_system_screen))
        }
    }

    /** С секретами — только в файл, после предупреждения (D-11). */
    private fun confirmFull(host: Host) {
        val c = host.activity
        Ui.secure(
            AlertDialog.Builder(c)
                .setTitle(R.string.export_full_title)
                .setMessage(R.string.export_full_text)
                .setPositiveButton(R.string.export_full_confirm) { _, _ ->
                    host.graph?.core?.export(ConfigWriter.Mode.FULL)?.let { host.saveDocument(FILE_FULL, it) }
                }
                .setNegativeButton(android.R.string.cancel, null)
                .show(),
        )
    }
}
