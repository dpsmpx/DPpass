package com.dpsmpx.dppass.app.ui

import android.app.Dialog
import com.dpsmpx.dppass.R
import com.dpsmpx.dppass.connection.ProviderPolicyStatus
import com.dpsmpx.dppass.core.SubscriptionId
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * Маршрутизация и DNS поставщика у подписки (D-98): что действует и окно
 * согласия. Включить — только увидев, что они заменят и что останется
 * своим (D-11); выключить — сразу. Применённая подписка загружается заново.
 */
object ProviderPolicySheet {
    fun show(host: Host, id: SubscriptionId) {
        val core = host.graph?.core ?: return
        val sub = core.subscriptions.state().valueOrNull()?.find(id) ?: return
        val c = host.activity
        val status = core.providerPolicyStatus(sub)
        val inUse = status != ProviderPolicyStatus.OFF
        lateinit var sheet: Dialog
        val body = Ui.column(c, 12).apply {
            addView(Ui.text(c, R.style.Text_DPpass_Body, c.getString(state(status))))
            if (!inUse) addView(Ui.text(c, R.style.Text_DPpass_Secondary, c.getString(R.string.provider_policy_confirm, sub.displayName)))
            addView(
                Ui.button(
                    c,
                    if (inUse) R.string.provider_policy_disable else R.string.provider_policy_enable,
                    if (inUse) Ui.Style.OUTLINE else Ui.Style.PRIMARY,
                    R.drawable.ic_route,
                ).apply {
                    setOnClickListener {
                        sheet.dismiss()
                        use(host, id, !inUse)
                    }
                },
                Ui.matchWidth(),
            )
        }
        sheet = Ui.sheet(c, c.getString(R.string.provider_policy_title), body)
        sheet.show()
    }

    fun state(status: ProviderPolicyStatus): Int = when (status) {
        ProviderPolicyStatus.OFF -> R.string.provider_policy_state_off
        ProviderPolicyStatus.IN_USE -> R.string.provider_policy_state_on
        ProviderPolicyStatus.NOT_APPLIED -> R.string.provider_policy_state_not_applied
        ProviderPolicyStatus.NOT_OFFERED -> R.string.provider_policy_state_not_offered
    }

    private fun use(host: Host, id: SubscriptionId, on: Boolean) {
        val graph = host.graph ?: return
        host.scope.launch {
            val r = withContext(Dispatchers.IO) { graph.core.subscriptions.setProviderPolicy(id, on, graph.fetcher, graph.appVersion) }
            SiteListsScreen.applied(host, r, if (on) R.string.provider_policy_on_done else R.string.provider_policy_off_done)
        }
    }
}
