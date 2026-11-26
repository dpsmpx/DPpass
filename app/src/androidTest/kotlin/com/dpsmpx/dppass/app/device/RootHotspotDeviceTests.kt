package com.dpsmpx.dppass.app.device

import android.net.LocalServerSocket
import android.net.LocalSocket
import android.net.LocalSocketAddress
import android.system.Os
import android.system.OsConstants
import android.system.StructPollfd
import com.dpsmpx.dppass.app.RootHotspotTunReceiver
import com.dpsmpx.dppass.diagnostics.Outcome
import com.dpsmpx.dppass.engine.xray.JniXrayRuntime
import com.dpsmpx.dppass.engine.xray.XrayResult
import java.io.File

/** D-120: отдельный запуск с внешним ROOT-помощником, не входит в обычный прогон. */
object RootHotspotDeviceTests : DeviceSuite {
    override val name = "RootHotspotManual"
    override val cases = listOf(DeviceCase("localAccessPoint") { device ->
        val activity = device.launch()
        val wifi = device.context.getSystemService(android.net.wifi.WifiManager::class.java)
        val result = java.util.concurrent.CompletableFuture<android.net.wifi.WifiManager.LocalOnlyHotspotReservation>()
        device.main {
            com.dpsmpx.dppass.app.RootHotspotLocalAccessPoint.request(
                wifi, android.os.Handler(android.os.Looper.getMainLooper()),
                { reservation -> if (!result.complete(reservation)) reservation.close() },
                { result.completeExceptionally(IllegalStateException("Точка доступа остановилась")) },
                { reason -> result.completeExceptionally(IllegalStateException("Отказ Android: $reason")) },
            )
        }
        try {
            result.get(20, java.util.concurrent.TimeUnit.SECONDS).use {
                expect(!activity.isFinishing) { "Экран закрыт во время запуска точки доступа" }
            }
        } finally {
            result.cancel(false)
        }
    }, DeviceCase("holdAccessPoint") { device -> withAccessPoint(device, false) },
        DeviceCase("accessPointAndTun") { device -> withAccessPoint(device, true) },
        DeviceCase("clientThroughTun") { device -> withAccessPoint(device, false, client = true) },
        DeviceCase("receiveTun", ::receiveTun))

    /**
     * Стенд D-120 с реальным клиентом: TUN приходит из основного namespace, выход —
     * blackhole. Пишет источники и цели соединений, увиденных ядром, без содержимого.
     */
    private fun clientThroughTun(device: Device, release: File, stopped: java.util.concurrent.CountDownLatch) {
        val cache = device.context.cacheDir
        val path = File(cache, "dppass-tun-probe.sock")
        val ready = File(cache, "dppass-lab-ap.ready")
        val seen = File(cache, "dppass-lab-ap.seen")
        expect(!path.exists()) { "Тестовый сокет уже существует" }
        ready.delete()
        seen.delete()
        var bound = false
        try {
            LocalSocket().use { socket ->
                socket.bind(LocalSocketAddress(path.absolutePath, LocalSocketAddress.Namespace.FILESYSTEM))
                bound = true
                val server = LocalServerSocket(socket.fileDescriptor)
                val poll = StructPollfd().apply {
                    this.fd = socket.fileDescriptor
                    events = OsConstants.POLLIN.toShort()
                }
                expect(Os.poll(arrayOf(poll), 60_000) == 1) { "ROOT-помощник не подключился" }
                server.accept().use { peer ->
                    RootHotspotTunReceiver.receive(peer, "dpgateway").use { tun ->
                        val loaded = JniXrayRuntime.load({ System.loadLibrary(JniXrayRuntime.LIBRARY) }, cache.path)
                        expect(loaded is Outcome.Success) { "Не удалось загрузить ядро" }
                        val runtime = (loaded as Outcome.Success).value
                        // Выход заблокирован: здесь проверяется только вход клиента в ядро.
                        val config = """
                            {
                              "stats": {},
                              "policy": {"system": {"statsOutboundUplink": true, "statsOutboundDownlink": true}},
                              "inbounds": [{"tag":"tun-in","protocol":"tun","settings":{"name":"dpgateway","mtu":1500}}],
                              "outbounds": [{"tag":"proxy","protocol":"blackhole"}]
                            }
                        """.trimIndent()
                        runtime.setConnectionTracking(true)
                        val started = runtime.start(config.encodeToByteArray(), tun.fd, 1500) { false }
                        expect(started == XrayResult.Ok) { "Ядро не приняло TUN: ${(started as? XrayResult.Failed)?.text ?: started}" }
                        try {
                            ready.writeText("ready\n")
                            val deadline = android.os.SystemClock.elapsedRealtime() + 120_000
                            while (!release.exists() && stopped.count > 0 && android.os.SystemClock.elapsedRealtime() < deadline) {
                                android.os.SystemClock.sleep(200)
                            }
                            // Адрес клиента и тестовую цель пишет стенд; содержимое потоков не сохраняется.
                            val expected = File(cache, "dppass-lab-ap.client").takeIf { it.isFile }?.readLines().orEmpty()
                            val matched = expected.size == 2 && runtime.connections().connections.any {
                                it.source.substringAfterLast("://").substringBeforeLast(':') == expected[0] &&
                                    it.target.substringAfterLast("://") == expected[1]
                            }
                            seen.writeText(if (matched) "matched\n" else "absent\n")
                        } finally {
                            expect(runtime.stop() == XrayResult.Ok) { "Ядро не остановилось" }
                        }
                    }
                }
            }
        } finally {
            ready.delete()
            if (bound) path.delete()
        }
    }

    private fun withAccessPoint(device: Device, testTun: Boolean, client: Boolean = false) {
        // Ручной стенд: параметры временной AP — только в приватном каталоге приложения.
        val activity = device.launch()
        val wifi = device.context.getSystemService(android.net.wifi.WifiManager::class.java)
        val result = java.util.concurrent.CompletableFuture<android.net.wifi.WifiManager.LocalOnlyHotspotReservation>()
        val stopped = java.util.concurrent.CountDownLatch(1)
        device.main {
            com.dpsmpx.dppass.app.RootHotspotLocalAccessPoint.request(
                wifi, android.os.Handler(android.os.Looper.getMainLooper()),
                { reservation -> if (!result.complete(reservation)) reservation.close() },
                { stopped.countDown() },
                { reason -> result.completeExceptionally(IllegalStateException("Отказ Android: $reason")) },
            )
        }
        val info = File(device.context.cacheDir, "dppass-lab-ap")
        val release = File(device.context.cacheDir, "dppass-lab-ap.stop")
        release.delete()
        try {
            result.get(20, java.util.concurrent.TimeUnit.SECONDS).use { reservation ->
                val config = checkNotNull(reservation.softApConfiguration)
                // getWifiSsid() появился в API 33; Zenfone — API 32.
                @Suppress("DEPRECATION")
                val ssid = if (android.os.Build.VERSION.SDK_INT >= 33) config.wifiSsid.toString().trim('"') else config.ssid
                info.writeText("$ssid\n${config.passphrase}\n")
                if (testTun) receiveTun(device)
                if (client) clientThroughTun(device, release, stopped)
                val deadline = android.os.SystemClock.elapsedRealtime() + 180_000
                while (!release.exists() && stopped.count > 0 && android.os.SystemClock.elapsedRealtime() < deadline) {
                    android.os.SystemClock.sleep(200)
                }
                expect(stopped.count > 0) { "Android остановил точку доступа раньше времени" }
                expect(!activity.isFinishing) { "Экран закрыт во время стенда" }
            }
        } finally {
            result.cancel(false)
            info.delete()
            release.delete()
        }
    }

    private fun receiveTun(device: Device) {
        val path = File(device.context.cacheDir, "dppass-tun-probe.sock")
        expect(!path.exists()) { "Тестовый сокет уже существует" }
        var bound = false
        try {
            LocalSocket().use { socket ->
                socket.bind(LocalSocketAddress(path.absolutePath, LocalSocketAddress.Namespace.FILESYSTEM))
                bound = true
                val fd = socket.fileDescriptor
                val server = LocalServerSocket(fd)
                val poll = StructPollfd().apply {
                    this.fd = fd
                    events = OsConstants.POLLIN.toShort()
                }
                expect(Os.poll(arrayOf(poll), 15_000) == 1) { "ROOT-помощник не подключился" }
                server.accept().use { peer ->
                    RootHotspotTunReceiver.receive(peer, "dpgateway").use { tun ->
                        val tunPoll = StructPollfd().apply {
                            this.fd = tun.fileDescriptor
                            events = OsConstants.POLLIN.toShort()
                        }
                        expect(Os.poll(arrayOf(tunPoll), 3_000) == 1 &&
                            tunPoll.revents.toInt() and OsConstants.POLLIN != 0) { "Нет пакета в TUN" }
                        val packet = ByteArray(1500)
                        val count = Os.read(tun.fileDescriptor, packet, 0, packet.size)
                        val payload = "dppass-tun-probe".encodeToByteArray()
                        expect(count == 28 + payload.size && packet[0] == 0x45.toByte() && packet[9] == 17.toByte() &&
                            packet.copyOfRange(28, count).contentEquals(payload)) { "Неожиданный пакет TUN" }
                        val loaded = JniXrayRuntime.load({ System.loadLibrary(JniXrayRuntime.LIBRARY) }, device.context.cacheDir.path)
                        expect(loaded is Outcome.Success) { "Не удалось загрузить ядро" }
                        val runtime = (loaded as Outcome.Success).value
                        // В этом тесте внешнего выхода нет, и любой сетевой сокет запрещён.
                        val config = """
                            {
                              "stats": {},
                              "policy": {"system": {"statsOutboundUplink": true, "statsOutboundDownlink": true}},
                              "inbounds": [{"tag":"tun-in","protocol":"tun","settings":{"name":"dpgateway","mtu":1500}}],
                              "outbounds": [{"tag":"proxy","protocol":"blackhole"}]
                            }
                        """.trimIndent()
                        runtime.setConnectionTracking(true)
                        val started = runtime.start(config.encodeToByteArray(), tun.fd, 1500) { false }
                        expect(started == XrayResult.Ok) { "Ядро не приняло ROOT TUN: ${(started as? XrayResult.Failed)?.text ?: started}" }
                        try {
                            val deadline = android.os.SystemClock.elapsedRealtime() + 3_000
                            fun observed() = runtime.connections().connections.any { it.target.contains("192.0.2.2:5353") }
                            while (!observed() &&
                                android.os.SystemClock.elapsedRealtime() < deadline) {
                                android.os.SystemClock.sleep(20)
                            }
                            expect(observed()) { "Диспетчер ядра не увидел тестовый UDP-поток" }
                        } finally {
                            expect(runtime.stop() == XrayResult.Ok) { "Ядро не остановилось" }
                        }
                    }
                }
            }
        } finally {
            if (bound) path.delete()
        }
    }
}
