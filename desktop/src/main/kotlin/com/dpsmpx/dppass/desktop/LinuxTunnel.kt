package com.dpsmpx.dppass.desktop

import com.dpsmpx.dppass.diagnostics.DiagCode
import com.dpsmpx.dppass.diagnostics.Diagnostic
import com.dpsmpx.dppass.diagnostics.ErrorSummary
import com.dpsmpx.dppass.diagnostics.Logger
import com.dpsmpx.dppass.diagnostics.Outcome
import com.dpsmpx.dppass.diagnostics.Safe
import com.dpsmpx.dppass.tunnel.TunnelHandle
import com.dpsmpx.dppass.tunnel.TunnelProvider
import com.dpsmpx.dppass.tunnel.TunnelSpec
import java.io.File
import java.io.IOException
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean

/** Итог команды: код выхода и вывод (stdout и stderr вместе). */
data class CommandResult(val code: Int, val output: String)

/** То, чем туннель Linux меняет систему: нативные вызовы моста и команды `ip`. В тестах — подделка. */
interface LinuxPlatform {
    /** Есть ли у процесса `CAP_NET_ADMIN` (D-74). */
    fun hasNetAdmin(): Boolean

    /** Включён ли IPv6 в системе: выключен — правил IPv6 не нужно, утекать нечему. */
    fun ipv6Enabled(): Boolean

    /** fd или −errno. */
    fun openTun(name: String): Int

    fun closeFd(fd: Int): Int

    /** 0 или −errno. */
    fun markSocket(fd: Int, mark: Int): Int

    fun ip(args: List<String>): CommandResult
}

/**
 * TUN Linux по [TunnelSpec] (D-74): права, политика приложений, уборка
 * прежнего, устройство, адреса, маршруты, правила. Любой отказ — откат
 * сделанного и диагностика `TUN_ESTABLISH_FAILED` с причиной.
 */
class LinuxTunnelProvider(
    private val platform: LinuxPlatform,
    private val selfPackage: String,
    private val log: Logger,
) : TunnelProvider {
    override suspend fun establish(spec: TunnelSpec): Outcome<TunnelHandle> {
        if (!platform.hasNetAdmin()) {
            return Outcome.failure(
                DiagCode.TUN_ESTABLISH_FAILED,
                "у процесса нет права CAP_NET_ADMIN — туннель не поднять; запустите DPpass ярлыком или командой dppass (через pkexec)",
            )
        }
        LinuxRoutes.appPolicyProblem(spec, selfPackage)?.let { return Outcome.failure(it) }
        // Правила прежнего запуска остаются и после смерти процесса — сначала убрать их.
        apply(LinuxRoutes.down())
        val fd = platform.openTun(LinuxRoutes.DEVICE)
        if (fd < 0) {
            val hint = if (fd == -EBUSY) " — устройство занято: DPpass уже запущен?" else ""
            return Outcome.failure(DiagCode.TUN_ESTABLISH_FAILED, "TUN ${LinuxRoutes.DEVICE} не открыт: errno ${-fd}$hint")
        }
        val ipv6 = platform.ipv6Enabled()
        apply(LinuxRoutes.up(spec, ipv6))?.let { failed ->
            apply(LinuxRoutes.down())
            platform.closeFd(fd)
            return Outcome.failure(failed)
        }
        log.info("linux_tunnel_up", "device" to Safe(LinuxRoutes.DEVICE), "ipv6" to ipv6, "routes" to spec.routes.size, "excluded" to spec.excludedRoutes.size)
        return Outcome.Success(LinuxTunnel(fd, spec))
    }

    /** Выполнить команды по порядку; первая неудачная (не уборка) — диагностика, дальше не идём. */
    private fun apply(commands: List<IpCommand>): Diagnostic? {
        for (c in commands) {
            if (c.cleanup) {
                // Удаление правила — пока удаляется: дубликаты после сбоев не держат трафик.
                for (i in 0 until if (c.untilFails) CLEANUP_REPEATS else 1) {
                    if (platform.ip(c.args).code != 0) break
                }
                continue
            }
            val r = platform.ip(c.args)
            if (r.code != 0) {
                return Diagnostic.error(DiagCode.TUN_ESTABLISH_FAILED, "туннель не поднят: «$c» — код ${r.code}")
                    .withCause(
                        Diagnostic(code = DiagCode.TUN_ESTABLISH_FAILED, message = "вывод ip", error = ErrorSummary("ip", r.output.trim().take(OUTPUT_LIMIT))),
                    )
            }
        }
        return null
    }

    private inner class LinuxTunnel(override val fd: Int, override val spec: TunnelSpec) : TunnelHandle {
        private val closed = AtomicBoolean(false)

        /** Метка вместо `VpnService.protect`: правило метки ведёт сокет в `main` (T4). */
        override fun protect(socketFd: Int): Boolean = platform.markSocket(socketFd, LinuxRoutes.MARK) == 0

        /** Правила — раньше fd: с закрытием fd исчезает устройство и его маршруты. */
        override fun close() {
            if (!closed.compareAndSet(false, true)) return
            apply(LinuxRoutes.down())
            platform.closeFd(fd)
            log.info("linux_tunnel_down", "device" to Safe(LinuxRoutes.DEVICE))
        }
    }

    private companion object {
        const val EBUSY = 16
        const val CLEANUP_REPEATS = 8
        const val OUTPUT_LIMIT = 500
    }
}

/** Настоящая платформа: мост ядра и `/usr/bin/ip`. */
class SystemLinuxPlatform(private val proc: File = File("/proc")) : LinuxPlatform {
    override fun hasNetAdmin(): Boolean = Capabilities.hasNetAdmin(readOrNull(File(proc, "self/status")))

    override fun ipv6Enabled(): Boolean {
        if (!File(proc, "net/if_inet6").exists()) return false
        return readOrNull(File(proc, "sys/net/ipv6/conf/all/disable_ipv6"))?.trim() != "1"
    }

    override fun openTun(name: String): Int = LinuxNative.nativeOpenTun(name.encodeToByteArray())

    override fun closeFd(fd: Int): Int = LinuxNative.nativeCloseFd(fd)

    override fun markSocket(fd: Int, mark: Int): Int = LinuxNative.nativeMarkSocket(fd, mark)

    override fun ip(args: List<String>): CommandResult {
        val binary = IP_BINARIES.map(::File).firstOrNull { it.canExecute() }
            ?: return CommandResult(NOT_FOUND, "нет iproute2: ни одного из ${IP_BINARIES.joinToString()}")
        return try {
            val p = ProcessBuilder(listOf(binary.path) + args).redirectErrorStream(true).start()
            p.outputStream.close()
            val output = p.inputStream.bufferedReader().use { it.readText() }
            if (!p.waitFor(TIMEOUT_SECONDS, TimeUnit.SECONDS)) {
                p.destroyForcibly()
                CommandResult(TIMED_OUT, "не завершилась за $TIMEOUT_SECONDS с")
            } else {
                CommandResult(p.exitValue(), output)
            }
        } catch (e: IOException) {
            CommandResult(NOT_FOUND, e.message ?: e.javaClass.simpleName)
        }
    }

    private fun readOrNull(f: File): String? = try {
        f.readText()
    } catch (_: IOException) {
        null
    }

    private companion object {
        /** Не из PATH: процесс с CAP_NET_ADMIN не запускает то, что подложили в PATH (T17). */
        val IP_BINARIES = listOf("/usr/bin/ip", "/usr/sbin/ip", "/sbin/ip", "/bin/ip")
        const val TIMEOUT_SECONDS = 10L
        const val NOT_FOUND = 127
        const val TIMED_OUT = 124
    }
}

/** Возможности процесса из `/proc/self/status`. */
object Capabilities {
    /** Номер `CAP_NET_ADMIN` (linux/capability.h). */
    const val CAP_NET_ADMIN: Int = 12

    fun hasNetAdmin(status: String?): Boolean {
        val line = status?.lineSequence()?.firstOrNull { it.startsWith("CapEff:") } ?: return false
        val caps = line.removePrefix("CapEff:").trim().toULongOrNull(16) ?: return false
        return caps and (1uL shl CAP_NET_ADMIN) != 0uL
    }
}
