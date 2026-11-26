package com.dpsmpx.dppass.app

import android.net.LocalSocket
import android.os.ParcelFileDescriptor
import android.system.Os
import android.system.OsConstants
import java.io.File

/** D-120: приём одного дескриптора от ROOT по уже подключённому приватному сокету. */
internal object RootHotspotTunReceiver {
    private const val TUN_DEVICE = (10L shl 8) or 200L

    fun receive(socket: LocalSocket, expectedInterface: String): ParcelFileDescriptor {
        require(expectedInterface.matches(Regex("[a-zA-Z0-9_-]{1,15}")))
        check(socket.peerCredentials.uid == 0) { "ROOT: неверный владелец канала TUN" }
        socket.soTimeout = 3_000
        val marker = socket.inputStream.read()
        val descriptors = socket.ancillaryFileDescriptors.orEmpty()
        try {
            check(marker == 'T'.code && descriptors.size == 1) { "ROOT: неверный ответ канала TUN" }
            val received = descriptors.single()
            val info = Os.fstat(received)
            // Linux misc device 10:200. Одного номера устройства недостаточно.
            check(OsConstants.S_ISCHR(info.st_mode) && info.st_rdev == TUN_DEVICE) {
                "ROOT: дескриптор не указывает на устройство TUN"
            }
            // Возвращаем собственную копию: исходные дескрипторы закрываются и при отказе.
            val copy = ParcelFileDescriptor.dup(received)
            try {
                val names = File("/proc/self/fdinfo/${copy.fd}").useLines { lines ->
                    lines.filter { it.startsWith("iff:") }.take(2).map { it.substringAfter(':').trim() }.toList()
                }
                check(names == listOf(expectedInterface)) { "ROOT: дескриптор не привязан к ожидаемому TUN" }
                return copy
            } catch (failure: Throwable) {
                runCatching { copy.close() }.exceptionOrNull()?.let(failure::addSuppressed)
                throw failure
            }
        } finally {
            descriptors.forEach { fd -> runCatching { Os.close(fd) } }
        }
    }
}
