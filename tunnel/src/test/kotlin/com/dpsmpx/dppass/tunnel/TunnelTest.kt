package com.dpsmpx.dppass.tunnel

import com.dpsmpx.dppass.config.ConfigLoader
import com.dpsmpx.dppass.core.Cidr
import com.dpsmpx.dppass.core.IpAddress
import com.dpsmpx.dppass.routing.AppPolicy
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class TunnelSpecBuilderTest {
    private val ir = ConfigLoader().load(File(System.getProperty("dppass.repoRoot"), "tests/data/configs/valid-multi.json").readText()).valueOrNull()!!.ir

    @Test
    fun ownPackageIsAlwaysOutsideAndAppRulesAreLowered() {
        val spec = TunnelSpecBuilder.build(ir, "com.dpsmpx.dppass", PlatformTraits(supportsExcludeRoute = true)).valueOrNull()!!
        assertEquals(AppPolicy.ExceptApps(setOf("com.example.bank", "com.example.gosapp", "com.dpsmpx.dppass")), spec.apps)
    }

    @Test
    fun ipv6IsAlwaysRoutedSoItCannotLeak() {
        val spec = TunnelSpecBuilder.build(ir, "com.dpsmpx.dppass", PlatformTraits(supportsExcludeRoute = true)).valueOrNull()!!
        assertTrue(Cidr.ALL_V6 in spec.routes)
        assertEquals(Ipv6Mode.TUNNELED, spec.ipv6Mode)
    }

    @Test
    fun oldAndroidGetsComplementRoutesInsteadOfExcludes() {
        val spec = TunnelSpecBuilder.build(ir, "com.dpsmpx.dppass", PlatformTraits(supportsExcludeRoute = false)).valueOrNull()!!
        assertTrue(spec.excludedRoutes.isEmpty())
        val lan = IpAddress.parse("192.168.1.10")!!
        val wan = IpAddress.parse("203.0.113.1")!!
        assertFalse(spec.routes.any { lan in it }, "локальная сеть не должна идти в туннель")
        assertTrue(spec.routes.any { wan in it })
        assertTrue(spec.routes.any { IpAddress.parse("2001:db8::1")!! in it })
        assertFalse(spec.routes.any { IpAddress.parse("fe80::1")!! in it })
    }

    @Test
    fun onlyAppsModeNeverIncludesSelf() {
        val only = ir.copy(routing = ir.routing.copy(apps = AppPolicy.OnlyApps(setOf("com.dpsmpx.dppass", "com.example.a")), rules = emptyList()))
        val spec = TunnelSpecBuilder.build(only, "com.dpsmpx.dppass", PlatformTraits(true)).valueOrNull()!!
        assertEquals(AppPolicy.OnlyApps(setOf("com.example.a")), spec.apps)
    }
}

class TunnelAppPolicyTest {
    private val ir = ConfigLoader().load(File(System.getProperty("dppass.repoRoot"), "tests/data/configs/valid-minimal.json").readText()).valueOrNull()!!.ir

    /** Пустой «только эти» Builder понял бы как «все» — смысл перевернулся бы молча (D-05, D-38). */
    @Test
    fun emptyOnlyAppsIsRejectedNotWidenedToAll() {
        val only = { pkgs: Set<String> -> ir.copy(routing = ir.routing.copy(apps = AppPolicy.OnlyApps(pkgs))) }
        val traits = PlatformTraits(supportsExcludeRoute = true)
        assertEquals(
            listOf(com.dpsmpx.dppass.diagnostics.DiagCode.APP_POLICY_CONFLICT),
            TunnelSpecBuilder.build(only(emptySet()), "com.dpsmpx.dppass", traits).errors.map { it.code },
        )
        // Только сам DPpass — тоже пусто: себя в туннель он не пускает никогда.
        assertFalse(TunnelSpecBuilder.build(only(setOf("com.dpsmpx.dppass")), "com.dpsmpx.dppass", traits).isSuccess)
        assertEquals(
            AppPolicy.OnlyApps(setOf("org.example.browser")),
            TunnelSpecBuilder.build(only(setOf("org.example.browser")), "com.dpsmpx.dppass", traits).valueOrNull()!!.apps,
        )
    }
}
