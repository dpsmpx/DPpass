package com.dpsmpx.dppass.connection

/**
 * Fixed upstream nfqws2 v1.0.7 Lua profiles; the user-supplied allowlist only
 * controls whether a fixed, root-owned file is attached to each filter.
 *
 * Arguments are assembled exclusively from literals and booleans, so neither
 * a user-supplied domain nor a shell fragment may become a command argument.
 */
object Zapret2RootProfiles {
    fun arguments(allHosts: Boolean, quic: Boolean): String {
        val hostArg = if (allHosts) "" else " --hostlist=hosts.txt"
        val profiles = listOf(
            "--filter-tcp=80 --filter-l7=http --payload=http_req" + hostArg +
                " --lua-desync=fake:blob=fake_default_http:tcp_md5" +
                " --lua-desync=multisplit:pos=method+2",
            "--filter-tcp=443 --filter-l7=tls --payload=tls_client_hello" + hostArg +
                " --lua-desync=fake:blob=fake_default_tls:tcp_md5:tcp_seq=-10000" +
                " --lua-desync=multidisorder:pos=1,midsld",
        ) + (if (quic) listOf(
            "--filter-udp=443 --filter-l7=quic --payload=quic_initial" + hostArg +
                " --lua-desync=fake:blob=fake_default_quic:repeats=6",
        ) else emptyList())
        return " --qnum=20529 --lua-init=@zapret-lib.lua --lua-init=@zapret-antidpi.lua " +
            profiles.joinToString(" --new ")
    }
}
