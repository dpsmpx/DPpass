package com.dpsmpx.dppass.app

import android.content.Context
import com.dpsmpx.dppass.connection.Zapret2Hostlist
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.File

/**
 * Original ciadpi transparent TCP mode using IPv4 and optional IPv6 OUTPUT REDIRECT.
 * No NFQUEUE, no UDP interception and no unprivileged raw sockets.
 * Dedicated rule and root-owned directory; never flush a system chain.
 */
internal class RootByeDpi(private val context: Context) :
    AdmittedRootDpiRuntime(RootDpiPreflight.Kind.SOCKET) {
    private val hostlist = AppPrefs(context).zapret2HostlistText
    private val lifecycle = RootLifecycleTransaction(
        ROOT, lockDirectory = RootLifecycleTransaction.SHARED_LOCK_DIRECTORY,
        peerDirectory = RootLifecycleTransaction.ZAPRET_DIRECTORY,
        peerCleanup = RootAdapterCleanup.zapret2(),
    )

    override fun launch(admission: RootDpiPreflight.Admission) {
        val binary = ByeDpiRuntime.executable(context)
        val hosts = Zapret2Hostlist.parse(hostlist).getOrThrow()
        val localHosts = File(context.noBackupFilesDir, "bd-root-hosts").apply {
            writeText(hosts.format() + "\n")
        }
        val helper = RootPidfdDeployment.stage(context)
        try {
            val owner = RootOwnerIdentity(android.os.Process.myPid(), RootProcessIdentity.currentAppStartTime())
            val script = launchScript(binary, localHosts, hosts.isEmpty, owner, helper, admission.ipv6Output)
            val startup = lifecycle.start(cleanup(), script, owner, preservePreviousOwner = true,
                prepare = helper?.install(ROOT) ?: ":")
            rootLaunchWithRollback(
                launch = { execute(startup) },
                rollback = { execute(lifecycle.stop(cleanup())) },
            )
        } finally {
            helper?.discard()
        }
    }

    private fun launchScript(
        binary: File, hosts: File, allHosts: Boolean, owner: RootOwnerIdentity,
        helper: RootPidfdDeployment.Staged?, enableIPv6: Boolean,
    ): String {
        val args = if (allHosts) ByeDpiRuntime.strategy
            else ByeDpiRuntime.strategy + listOf("--hosts", "$ROOT/hosts", "--auto=none")
        fun command(address: String) = (listOf("$ROOT/ciadpi", "--ip", address, "--port", PORT.toString(),
            "--transparent", "--no-domain") + args).joinToString(" ") { quote(it) }
        val watchdog = lifecycle.watchdog(
            RootProcessIdentity.appAlive(owner.pid, owner.startTime) + " && " + healthy(),
            cleanup(false),
        )
        val lines = mutableListOf(
            "set -eu", "umask 077", "mkdir -p " + quote(ROOT), "chmod 700 " + quote(ROOT),
            if (helper != null) RootPidfdCleanup.requireForLaunch(ROOT) else ":",
            "cp " + quote(binary.absolutePath) + " " + quote("$ROOT/ciadpi"),
            "chmod 700 " + quote("$ROOT/ciadpi"),
            "cp " + quote(hosts.absolutePath) + " " + quote("$ROOT/hosts"),
            startListener(command("127.0.0.1"), "pid", "log"),
            "cat > " + quote("$ROOT/watch.sh") + " <<'DPPASS_BD_WATCH'\n" + watchdog + "\nDPPASS_BD_WATCH",
            RootProcessIdentity.detachedWatchdog("$ROOT/watch.sh", "$ROOT/watch.log"),
            "echo \"\$!\" > " + quote("$ROOT/watch.pid"),
            lifecycle.captureWatchdog("$ROOT/watch.sh"),
            "iptables -t nat -I OUTPUT " + RULE,
            "iptables -t nat -C OUTPUT " + RULE,
        )
        if (enableIPv6) {
            lines += RootFirewallCleanup.optionalIPv6(RootFirewallCleanup.Kind.SOCKET, "$ROOT/ipv6.intent", listOf(
                startListener(command("::1"), "pid6", "log6"),
                RootFirewallCleanup.markIntent("$ROOT/ipv6.intent"),
                "ip6tables -t nat -I OUTPUT " + RULE,
                "ip6tables -t nat -C OUTPUT " + RULE,
            ))
        }
        return lines.joinToString("\n")
    }

    private fun startListener(command: String, pidFile: String, log: String): String = listOf(
        RootProcessIdentity.detachedCommand(command, "$ROOT/$log"),
        "pid=\$!",
        "echo \"\$pid\" > " + quote("$ROOT/$pidFile"),
        "sleep 1",
        RootProcessIdentity.executableAlive("$ROOT/$pidFile", "$ROOT/ciadpi"),
        lifecycle.captureExecutable(pidFile, "$ROOT/ciadpi"),
        lifecycle.executableHealthy(pidFile, "$ROOT/ciadpi"),
    ).joinToString("\n")

    override suspend fun stop(): Result<Unit> = withContext(Dispatchers.IO) { runCatching { execute(lifecycle.stop(cleanup())) } }
    override suspend fun alive(): Boolean = withContext(Dispatchers.IO) {
        runCatching { execute(lifecycle.alive(healthy())) }.isSuccess
    }

    private fun healthy(): String =
        lifecycle.executableHealthy("pid", "$ROOT/ciadpi") +
            " && iptables -t nat -C OUTPUT " + RULE +
            " && " + lifecycle.executableHealthy("pid6", "$ROOT/ciadpi", optional = true) +
            " && { if test -e " + quote("$ROOT/pid6") + " || test -e " + quote("$ROOT/ipv6.intent") +
            " || test -L " + quote("$ROOT/ipv6.intent") + "; then " +
            "test -f " + quote("$ROOT/pid6") + " && test ! -L " + quote("$ROOT/ipv6.intent") +
            " && ip6tables -t nat -C OUTPUT " + RULE + "; else :; fi; }"

    private fun cleanup(stopWatch: Boolean = true): String = RootAdapterCleanup.byeDpi(stopWatch)

    private fun execute(script: String) {
        val result = RootCommandRunner.run(listOf("su", "-c", script))
        check(result.exitCode == 0) { "ByeDPI root: " + result.outputTail }
    }

    private fun quote(raw: String): String = "'" + raw.replace("'", "'\\''") + "'"

    private companion object {
        const val ROOT = RootLifecycleTransaction.BYEDPI_DIRECTORY
        const val PORT = 40529
        // Exclude daemon's root-owned sockets and local destinations to avoid recursion.
        const val RULE = RootAdapterCleanup.BYEDPI_RULE
    }
}
