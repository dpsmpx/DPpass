package com.dpsmpx.dppass.app.device

import android.net.LocalServerSocket
import android.net.LocalSocket
import android.net.LocalSocketAddress
import android.system.Os
import android.system.OsConstants
import android.system.StructPollfd
import com.dpsmpx.dppass.app.RootHotspotTunReceiver
import java.io.File

/** D-120: отдельный запуск с внешним ROOT-помощником, не входит в обычный прогон. */
object RootHotspotDeviceTests : DeviceSuite {
    override val name = "RootHotspotManual"
    override val cases = listOf(DeviceCase("receiveTun") { device ->
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
                        expect(tun.fd >= 0) { "Дескриптор TUN закрыт" }
                    }
                }
            }
        } finally {
            if (bound) path.delete()
        }
    })
}
