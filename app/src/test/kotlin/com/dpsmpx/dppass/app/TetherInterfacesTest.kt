package com.dpsmpx.dppass.app

import com.dpsmpx.dppass.app.TetherInterfaces.Address
import com.dpsmpx.dppass.app.TetherInterfaces.Iface
import com.dpsmpx.dppass.core.IpAddress
import com.dpsmpx.dppass.engine.ShareSpec
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/** Интерфейсы раздачи (D-51): что считается раздачей и когда переподключаться. */
class TetherInterfacesTest {
    private fun ip(s: String) = IpAddress.parse(s)!!

    private fun iface(name: String, addr: String, prefix: Int = 24, up: Boolean = true, p2p: Boolean = false, loopback: Boolean = false, broadcast: Boolean = true) =
        Iface(name, up, loopback, p2p, listOf(Address(ip(addr), prefix, broadcast)))

    private fun ep(addr: String, prefix: Int = 24) = ShareSpec.Endpoint(ip(addr), prefix)

    @Test
    fun onlyDownstreamPrivateBroadcastInterfaces() {
        val all = listOf(
            iface("wlan0", "192.168.1.5"), // Wi-Fi-клиент: сеть ConnectivityManager
            iface("rmnet_data0", "10.120.4.7", prefix = 30), // мобильная связь: тоже сеть
            iface("tun0", "172.19.0.1", prefix = 30, p2p = true, broadcast = false), // TUN DPpass
            iface("lo", "127.0.0.1", prefix = 8, loopback = true),
            iface("swlan0", "192.168.43.1"), // точка доступа
            iface("rndis0", "192.168.42.129"), // USB-модем
            iface("bt-pan", "192.168.44.1"), // Bluetooth-модем
            iface("ap1", "192.168.45.1", up = false), // выключена
            iface("ccmni1", "10.0.0.2", prefix = 24, broadcast = false), // точка-точка без пометки
            iface("odd0", "198.51.100.1"), // не частный адрес
            iface("odd1", "192.168.46.1", prefix = 32), // нет места для клиентов
        )
        val chosen = TetherInterfaces.select(all, upstream = setOf("wlan0", "rmnet_data0", "tun0"))
        assertEquals(listOf(ep("192.168.42.129"), ep("192.168.43.1"), ep("192.168.44.1")), chosen)
    }

    // D-57: Redmi 13, Android 15 — раздача не нашлась по признакам. Названное системой
    // берётся и когда значится сетью, и без широковещания; не названное — нет.
    @Test
    fun systemNamedInterfacesWinOverHeuristics() {
        val all = listOf(
            iface("wlan0", "192.168.1.5"), // Wi-Fi-клиент
            iface("wlan1", "192.168.120.1", broadcast = false), // точка доступа: значится сетью, без широковещания
            iface("rmnet_data1", "10.120.4.7", prefix = 24), // IMS: частный адрес, но не раздача
            iface("ap1", "192.168.45.1", up = false), // названа, но выключена
            iface("lo", "127.0.0.1", prefix = 8, loopback = true),
        )
        val named = TetherInterfaces.selectNamed(all, setOf("wlan1", "ap1", "lo"))
        assertEquals(listOf(ep("192.168.120.1")), named)
        assertEquals(emptyList(), TetherInterfaces.select(all, upstream = setOf("wlan0", "wlan1", "rmnet_data1")), "по признакам — не нашлась бы")
        assertEquals(emptyList(), TetherInterfaces.selectNamed(listOf(iface("wlan1", "203.0.113.1")), setOf("wlan1")), "только частный IPv4")
    }

    @Test
    fun wlanClientIsExcludedOnlyAsDeviceNetwork() {
        // Wi-Fi-клиент отсеивается только как сеть устройства: поэтому без сведений
        // о сетях find() не выбирает ничего, а не всё подряд.
        val wlan = iface("wlan0", "192.168.1.5")
        assertEquals(emptyList(), TetherInterfaces.select(listOf(wlan), upstream = setOf("wlan0")))
        assertEquals(listOf(ep("192.168.1.5")), TetherInterfaces.select(listOf(wlan), upstream = emptySet()))
    }

    @Test
    fun goneInterfaceReconnectsAtOnceNewOneAfterTwoPolls() {
        val hotspot = ep("192.168.43.1")
        val usb = ep("192.168.42.129")
        assertFalse(TetherInterfaces.shouldReconnect(listOf(hotspot), listOf(hotspot), null), "ничего не изменилось")
        assertTrue(TetherInterfaces.shouldReconnect(listOf(hotspot, usb), listOf(hotspot), null), "модем выключен — сразу")
        assertTrue(TetherInterfaces.shouldReconnect(listOf(hotspot), emptyList(), null), "точка доступа выключена — сразу")
        assertFalse(TetherInterfaces.shouldReconnect(emptyList(), listOf(hotspot), null), "новый — ещё не подтверждён")
        assertTrue(TetherInterfaces.shouldReconnect(emptyList(), listOf(hotspot), listOf(hotspot)), "виден второй опрос подряд")
        assertFalse(TetherInterfaces.shouldReconnect(emptyList(), listOf(hotspot), listOf(usb)), "прошлый опрос видел другое")
    }

    @Test
    fun connectUsesOnlyAddressesSeenTwice() {
        val hotspot = ep("192.168.43.1")
        val wlanBlink = ep("192.168.1.50") // сеть Wi-Fi-клиента на миг не значилась в ConnectivityManager
        assertEquals(listOf(hotspot), TetherInterfaces.confirmed(listOf(hotspot, wlanBlink), listOf(hotspot)))
        assertEquals(emptyList(), TetherInterfaces.confirmed(listOf(hotspot), emptyList()), "точку доступа выключили между снимками")
        assertEquals(emptyList(), TetherInterfaces.confirmed(emptyList(), listOf(hotspot)), "новый — только со следующего опроса")
    }
}
