package com.dpsmpx.dppass.app

import android.Manifest
import android.content.Context
import android.content.pm.PackageManager
import android.location.LocationManager
import android.net.wifi.WifiManager
import android.os.Build

/** Read permission/capability state only. Never requests permission,
 * reads location, enables Wi-Fi, creates an AP or changes system settings. */
internal object RootHotspotWifiReadiness {
    enum class Check { WIFI_HARDWARE, WIFI_SERVICE, WIFI_PERMISSION, LOCATION_ENABLED }
    data class Facts(val sdk: Int, val hardware: Boolean, val service: Boolean,
                     val granted: Set<String>, val locationEnabled: Boolean)
    data class Report(val failed: Set<Check>, val missingPermissions: Set<String>)

    fun requiredPermissions(sdk: Int): Set<String> = if (sdk >= 33) {
        setOf(Manifest.permission.NEARBY_WIFI_DEVICES)
    } else {
        setOf(Manifest.permission.ACCESS_FINE_LOCATION, Manifest.permission.ACCESS_COARSE_LOCATION)
    }

    fun evaluate(facts: Facts): Report {
        val missing = requiredPermissions(facts.sdk) - facts.granted
        val failed = buildSet {
            if (!facts.hardware) add(Check.WIFI_HARDWARE)
            if (!facts.service) add(Check.WIFI_SERVICE)
            if (missing.isNotEmpty()) add(Check.WIFI_PERMISSION)
            if (facts.sdk < 33 && !facts.locationEnabled) add(Check.LOCATION_ENABLED)
        }
        return Report(failed, missing)
    }

    fun inspect(context: Context): Report {
        val app = context.applicationContext
        val sdk = Build.VERSION.SDK_INT
        val hardware = runCatching {
            app.packageManager.hasSystemFeature(PackageManager.FEATURE_WIFI)
        }.getOrDefault(false)
        val service = runCatching {
            app.getSystemService(WifiManager::class.java) != null
        }.getOrDefault(false)
        val granted = requiredPermissions(sdk).filterTo(mutableSetOf()) {
            app.checkSelfPermission(it) == PackageManager.PERMISSION_GRANTED
        }
        val location = if (sdk >= 33) true else runCatching {
            val manager = app.getSystemService(LocationManager::class.java) ?: return@runCatching false
            if (sdk >= 28) manager.isLocationEnabled else
                manager.isProviderEnabled(LocationManager.GPS_PROVIDER) ||
                    manager.isProviderEnabled(LocationManager.NETWORK_PROVIDER)
        }.getOrDefault(false)
        return evaluate(Facts(sdk, hardware, service, granted, location))
    }
}
