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
internal class RootByeDpi(private val context: Context) : RootDpiRuntime {
    private val lifecycle = RootLifecycleTransaction(
        ROOT, lockDirectory = RootLifecycleTransaction.SHARED_LOCK_DIRECTORY,
        peerDirectory = RootLifecycleTransaction.ZAPRET_DIRECTORY,
        peerCleanup = RootAdapterCleanup.zapret2(),
    )

    override suspend fun start(): Result<Unit> = withContext(Dispatchers.IO) {
        runCatching {
            // Read-only preflight, only after explicit selection of ROOT.
            RootDpiPreflight.requireReady(RootDpiPreflight.Kind.SOCKET)
            val binary = ByeDpiRuntime.executable(context)
            val hosts = Zapret2Hostlist.parse(AppPrefs(context).zapret2HostlistText).getOrThrow()
            val localHosts = File(context.noBackupFilesDir, "bd-root-hosts").apply {
                writeText(hosts.format() + "\n")
            }
            val helper = RootPidfdDeployment.stage(context)
            try {
                rootLaunchWithRollback(launch = {
                val args = if (hosts.isEmpty) ByeDpiRuntime.strategy
                    else ByeDpiRuntime.strategy + listOf("--hosts", "$ROOT/hosts", "--auto=none")
                fun command(address: String) = (listOf("$ROOT/ciadpi", "--ip", address, "--port", PORT.toString(),
                    "--transparent", "--no-domain") + args).joinToString(" ") { quote(it) }
                val cmd = command("127.0.0.1")
                val cmd6 = command("::1")
                val owner = RootOwnerIdentity(android.os.Process.myPid(), RootProcessIdentity.currentAppStartTime())
                val watch = lifecycle.watchdog(
                    RootProcessIdentity.appAlive(owner.pid, owner.startTime) + " && " + healthy(),
                    cleanup(false),
                )
                execute(lifecycle.start(cleanup(), listOf("set -eu", "umask 077", "mkdir -p " + quote(ROOT),
                    "chmod 700 " + quote(ROOT), if (helper != null) RootPidfdCleanup.requireForLaunch(ROOT) else ":",
                    "cp " + quote(binary.absolutePath) + " " + quote("$ROOT/ciadpi"),
                    "chmod 700 " + quote("$ROOT/ciadpi"),
                    "cp " + quote(localHosts.absolutePath) + " " + quote("$ROOT/hosts"),
                    RootProcessIdentity.detachedCommand(cmd, "$ROOT/log"),
                    "pid=$!", "echo \"\$pid\" > " + quote("$ROOT/pid"), "sleep 1", RootProcessIdentity.executableAlive("$ROOT/pid", "$ROOT/ciadpi"),
                    lifecycle.captureExecutable("pid", "$ROOT/ciadpi"),
                    "cat > " + quote("$ROOT/watch.sh") + " <<'DPPASS_BD_WATCH'\n" + watch + "\nDPPASS_BD_WATCH",
                    RootProcessIdentity.detachedWatchdog("$ROOT/watch.sh", "$ROOT/watch.log"),
                    "echo \"\$!\" > " + quote("$ROOT/watch.pid"),
                    lifecycle.captureWatchdog("$ROOT/watch.sh"),
                    "iptables -t nat -I OUTPUT " + RULE,
                    "iptables -t nat -C OUTPUT " + RULE,
                    // Do not claim IPv6 interception on kernels without IPv6 NAT.
                    RootFirewallCleanup.optionalIPv6(RootFirewallCleanup.Kind.SOCKET, "$ROOT/ipv6.intent", listOf(
                        RootProcessIdentity.detachedCommand(cmd6, "$ROOT/log6"),
                        "pid=$!", "echo \"\$pid\" > " + quote("$ROOT/pid6"), "sleep 1", RootProcessIdentity.executableAlive("$ROOT/pid6", "$ROOT/ciadpi"),
                        lifecycle.captureExecutable("pid6", "$ROOT/ciadpi"),
                        RootFirewallCleanup.markIntent("$ROOT/ipv6.intent"),
                        "ip6tables -t nat -I OUTPUT " + RULE, "ip6tables -t nat -C OUTPUT " + RULE,
                    ))).joinToString("\n"), owner, preservePreviousOwner = true, prepare = helper?.install(ROOT) ?: ":"))
                }, rollback = { execute(lifecycle.stop(cleanup())) })
            } finally {
                helper?.discard()
            }
        }
    }

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
