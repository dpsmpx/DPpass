package com.dpsmpx.dppass.app.ui

import android.app.AlertDialog
import com.dpsmpx.dppass.R
import com.dpsmpx.dppass.app.RootDpiPreflight
import com.dpsmpx.dppass.connection.Zapret2Backend
import com.dpsmpx.dppass.connection.Zapret2VpnStrategy

/** Shared executor picker. Reference paths remain explicit and separate. */
internal object LocalBackendChoice {
    fun label(backend: Zapret2Backend): Int = when (backend) {
        Zapret2Backend.OFF -> R.string.zapret2_off
        Zapret2Backend.VPN_SERVICE -> R.string.local_backend_auto
        Zapret2Backend.ROOT -> R.string.local_backend_root
        Zapret2Backend.BYEDPI_VPN -> R.string.local_backend_byedpi_vpn
        Zapret2Backend.BYEDPI_ROOT -> R.string.local_backend_byedpi_root
    }

    fun show(host: Host, includeProvider: Boolean) {
        val activity = host.activity
        val expected = host.prefs.zapret2Backend
        val choices = listOf(Zapret2Backend.VPN_SERVICE, Zapret2Backend.ROOT,
            Zapret2Backend.BYEDPI_VPN, Zapret2Backend.BYEDPI_ROOT)
        val options = (if (includeProvider) listOf(Zapret2Backend.OFF) + choices else choices)
            .filter { !it.rooted || RootDpiPreflight.permitsLegacyRoot(activity.packageName) }
        val selected = options.indexOf(expected)
        val labels = options.map { activity.getString(label(it)) }.toTypedArray()
        Ui.secure(AlertDialog.Builder(activity)
            .setTitle(R.string.local_backend_choose)
            .setSingleChoiceItems(labels, selected) { dialog, which ->
                dialog.dismiss()
                if (host.prefs.zapret2Backend != expected) {
                    host.toast(activity.getString(R.string.local_backend_changed))
                } else select(host, options[which])
            }.setNegativeButton(android.R.string.cancel, null).show())
    }

    fun select(host: Host, requested: Zapret2Backend) {
        val expected = host.prefs.zapret2Backend
        if (requested == expected) return
        val activity = host.activity
        if (requested.rooted && !RootDpiPreflight.permitsLegacyRoot(activity.packageName)) {
            host.toast(activity.getString(R.string.local_backend_root_unavailable))
            return
        }
        fun apply() {
            if (host.prefs.zapret2Backend != expected) {
                host.toast(activity.getString(R.string.local_backend_changed))
                return
            }
            host.prefs.zapret2Backend = requested
            if (requested == Zapret2Backend.VPN_SERVICE) host.prefs.zapret2VpnStrategy = Zapret2VpnStrategy.AUTO
            host.reconnectIfBusy()
            host.changed()
        }
        if (Zapret2Backend.requiresRootConfirmation(expected, requested)) {
            Ui.secure(AlertDialog.Builder(activity).setTitle(R.string.local_backend_confirm)
                .setMessage(activity.getString(R.string.local_backend_root_confirm, activity.getString(label(requested))))
                .setNegativeButton(android.R.string.cancel, null)
                .setPositiveButton(R.string.local_backend_confirm) { _, _ -> apply() }.show())
        } else apply()
    }
}
