package com.dpsmpx.dppass.app

import com.dpsmpx.dppass.engine.DesyncTrick
import com.dpsmpx.dppass.engine.ServerlessPlan
import com.dpsmpx.dppass.engine.xray.XrayCompiler
import com.dpsmpx.dppass.routing.DnsPolicy
import com.dpsmpx.dppass.routing.SplitSites

/** D-120: запросы локального шлюза проходят через штатный планировщик без сервера. */
internal object RootHotspotLocalPlan {
    fun compile(dns: DnsPolicy) = XrayCompiler(dnsHijackAnyAddress = true).compileServerless(
        ServerlessPlan(dns = dns, splitSites = SplitSites(), splitRest = true, desync = DesyncTrick.Auto),
    )
}
