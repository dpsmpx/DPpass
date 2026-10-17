package com.dpsmpx.dppass.app.ui

import android.app.Activity
import android.app.AlertDialog
import com.dpsmpx.dppass.R
import com.dpsmpx.dppass.connection.Pairing
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.withTimeoutOrNull

/**
 * Код сопряжения (D-56) — окном, одинаково на обоих телефонах:
 * «Совпадает» — да; «Нет», закрытие окна или конец окна сопряжения — нет.
 * Вызывать на главном потоке.
 */
internal object PairingDialog {
    suspend fun ask(activity: Activity, code: String): Boolean {
        val answer = CompletableDeferred<Boolean>()
        val dialog = AlertDialog.Builder(activity)
            .setTitle(R.string.pairing_code_title)
            .setMessage(activity.getString(R.string.pairing_code_text, code.chunked(3).joinToString(" ")))
            .setPositiveButton(R.string.pairing_code_match) { _, _ -> answer.complete(true) }
            .setNegativeButton(R.string.pairing_code_mismatch) { _, _ -> answer.complete(false) }
            // После кнопки окно тоже закрывается: complete второй раз ничего не меняет.
            .setOnDismissListener { answer.complete(false) }
            .show()
        Ui.secure(dialog)
        return try {
            withTimeoutOrNull(Pairing.WINDOW_MILLIS) { answer.await() } ?: false
        } finally {
            if (dialog.isShowing) dialog.dismiss()
        }
    }
}
