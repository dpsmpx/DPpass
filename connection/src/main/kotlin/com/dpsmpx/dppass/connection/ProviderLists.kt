package com.dpsmpx.dppass.connection

import com.dpsmpx.dppass.core.SubscriptionId
import com.dpsmpx.dppass.diagnostics.Diagnostic
import com.dpsmpx.dppass.routing.SiteListsChange

/**
 * Списки поставщика подписки (D-94) — для экрана: что в профиле, что не
 * взято и почему, что изменилось с прежним профилем и действуют ли они.
 * Свои списки — поверх: при совпадении записи решает своя.
 */
data class ProviderListsView(
    val subscription: SubscriptionId,
    /** Разобранный профиль; null — не разобран ([problem]). */
    val profile: HappRoutingImport?,
    val problem: Diagnostic?,
    val receivedAtMillis: Long,
    /** Что изменилось с прежним профилем; null — прежнего нет или он не разобран. */
    val change: SiteListsChange?,
    val previousAtMillis: Long?,
    /** Пользователь включил списки поставщика у этой подписки. */
    val inUse: Boolean,
    /** Подписка применена сейчас: списки действуют, если ещё и [inUse]. */
    val applied: Boolean,
)
