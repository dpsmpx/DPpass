package com.dpsmpx.dppass.app

import android.Manifest
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class RootHotspotWifiReadinessTest {
    private val nearby = Manifest.permission.NEARBY_WIFI_DEVICES
    private val fine = Manifest.permission.ACCESS_FINE_LOCATION
    private val coarse = Manifest.permission.ACCESS_COARSE_LOCATION
    private val modern = RootHotspotWifiReadiness.Facts(33, true, true, setOf(nearby), false)
    private val legacy = modern.copy(sdk = 32, granted = setOf(fine, coarse), locationEnabled = true)

    @Test fun modernDoesNotRequireLocationPermissionOrLocationService() {
        assertTrue(RootHotspotWifiReadiness.evaluate(modern).failed.isEmpty())
        assertEquals(setOf(nearby), RootHotspotWifiReadiness.requiredPermissions(35))
    }

    @Test fun legacyRequiresBothPermissionsAndLocationEnabled() {
        assertTrue(RootHotspotWifiReadiness.evaluate(legacy).failed.isEmpty())
        val report = RootHotspotWifiReadiness.evaluate(legacy.copy(granted = setOf(coarse), locationEnabled = false))
        assertEquals(setOf(fine), report.missingPermissions)
        assertEquals(setOf(RootHotspotWifiReadiness.Check.WIFI_PERMISSION,
            RootHotspotWifiReadiness.Check.LOCATION_ENABLED), report.failed)
    }

    @Test fun missingHardwareAndServiceAreIndependentFailures() {
        val report = RootHotspotWifiReadiness.evaluate(modern.copy(hardware = false, service = false))
        assertEquals(setOf(RootHotspotWifiReadiness.Check.WIFI_HARDWARE,
            RootHotspotWifiReadiness.Check.WIFI_SERVICE), report.failed)
    }

    @Test fun legacyPermissionsCannotReplaceNearbyPermissionOnModernAndroid() {
        val report = RootHotspotWifiReadiness.evaluate(modern.copy(granted = setOf(fine, coarse)))
        assertEquals(setOf(nearby), report.missingPermissions)
        assertEquals(setOf(RootHotspotWifiReadiness.Check.WIFI_PERMISSION), report.failed)
    }
}
