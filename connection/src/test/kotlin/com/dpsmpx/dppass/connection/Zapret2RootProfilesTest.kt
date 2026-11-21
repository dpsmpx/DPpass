package com.dpsmpx.dppass.connection

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class Zapret2RootProfilesTest {
    @Test fun threeProfilesWhenQuicOn() {
        val args = Zapret2RootProfiles.arguments(allHosts = true, quic = true)
        assertEquals(2, " --new ".toRegex().findAll(args).count())
        assertTrue(args.contains("--filter-tcp=80"))
        assertTrue(args.contains("--filter-tcp=443"))
        assertTrue(args.contains("--filter-udp=443"))
        assertFalse(args.contains("--hostlist="))
    }

    @Test fun onlyTcpWhenQuicOff() {
        val args = Zapret2RootProfiles.arguments(allHosts = false, quic = false)
        assertEquals(1, " --new ".toRegex().findAll(args).count())
        assertFalse(args.contains("--filter-udp="))
        assertEquals(2, "--hostlist=hosts.txt".toRegex().findAll(args).count())
    }

    @Test fun hostlistOnEveryProfile() {
        val args = Zapret2RootProfiles.arguments(allHosts = false, quic = true)
        assertEquals(3, "--hostlist=hosts.txt".toRegex().findAll(args).count())
    }
}
