package com.dpsmpx.dppass.app

import java.util.UUID
import com.dpsmpx.dppass.engine.TunInput
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class RootHotspotTunSetupTest {
    private val session = RootHotspotAdmission.Session(9, 12, RootHotspotAdmission.Mode.VPN)
    private val identity = RootHotspotTunLifetime.Identity(session, "dpgateway", 42)
    private val receipt = RootHotspotTunLaunch.Receipt(identity, 123)
    private val setup = RootHotspotTunSetup(identity, 1400)

    @Test fun validatesIdentityBeforeAnyMutationAndAfterLinkUp() {
        val body = setup.configure()
        val index = "test \"\$(cat /sys/class/net/dpgateway/ifindex)\" = '42'"
        val first = body.indexOf(index)
        val ipv6 = body.indexOf("> /proc/sys/net/ipv6/conf/dpgateway/disable_ipv6")
        val up = body.indexOf("ip link set dev dpgateway mtu 1400 up")
        assertTrue(first >= 0 && first < ipv6 && ipv6 < up && body.lastIndexOf(index) > up)
        assertTrue(body.indexOf("ip -6 -o addr show dev dpgateway") < ipv6)
    }

    @Test fun verificationChecksMtuTypeFlagsIpv6AndBothAddressFamilies() {
        val body = setup.verify()
        for (needle in listOf("/ifindex", "/type", "/tun_flags", "0x1001", "/mtu",
            "disable_ipv6", "ip -4 -o addr", "ip -6 -o addr", "count != 1")) assertTrue(body.contains(needle), needle)
        assertFalse(body.contains("ip link set"))
        assertFalse(body.contains("printf '1\\n' >"))
    }

    @Test fun neverChangesGlobalSettingsRoutesOrAddresses() {
        val body = setup.configure()
        for (needle in listOf("ip route", "ip rule", "iptables", "ip addr add",
            "ip link del", "/conf/all/", "/conf/default/", "ip_forward")) assertFalse(body.contains(needle), needle)
    }

    @Test fun invalidMtuAndForeignTunRejected() {
        for (mtu in listOf(0, 575, 1501)) assertThrows(IllegalArgumentException::class.java) {
            RootHotspotTunSetup(identity, mtu)
        }
        assertThrows(IllegalArgumentException::class.java) {
            RootHotspotTunSetup(identity.copy(name = "other"), 1400)
        }
    }

    @Test fun claimRejectsForeignReceiptAndWrapsSetupInExactLock() {
        val claim = RootHotspotClaim(session, owner = RootHotspotOwner(
            RootOwnerIdentity(123, "456"), UUID.randomUUID()), networkSlot = RootHotspotNetworkFixture.slot)
        val body = claim.tunSetup(receipt, 1400, true)
        assertTrue(body.indexOf("flock -x -n 9") < body.indexOf("ip link set"))
        assertTrue(body.indexOf("hotspot.owner") < body.indexOf("ip link set"))
        assertThrows(IllegalArgumentException::class.java) {
            claim.tunSetup(receipt.copy(identity = identity.copy(session = session.copy(generation = 10))), 1400, true)
        }
    }

    @Test fun runtimeHealthRequiresInitializedInputAndFreshLinkProof() {
        val observed = RootHotspotInterfaceEvidence.parse(
            "1: lo: <LOOPBACK> mtu 65536\n42: dpgateway: <UP> mtu 1400\n",
            "1: lo inet 127.0.0.1/8 scope host lo\n")
        var healthy = true
        var calls = 0
        val tun = RootHotspotTunLifetime(identity, { calls++; TunInput(42, 1400) { true } },
            {}, { observed }, { true }, { healthy })
        assertFalse(tun.healthy())
        assertEquals(42, tun.input.fd)
        assertTrue(tun.healthy())
        healthy = false
        assertFalse(tun.healthy())
        assertEquals(1, calls)
        tun.close()
        assertFalse(tun.healthy())
    }
}
