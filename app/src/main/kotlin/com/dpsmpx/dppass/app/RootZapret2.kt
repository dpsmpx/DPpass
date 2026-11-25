package com.dpsmpx.dppass.app

import android.content.Context
import android.os.Build
import com.dpsmpx.dppass.connection.Zapret2Hostlist
import com.dpsmpx.dppass.connection.Zapret2RootProfiles
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.File

/**
 * Experimental rooted Zapret2 adapter. Requires su, iptables NFQUEUE target,
 * a kernel that supports NFQUEUE, and execution allowed under /data/adb.
 * Does not establish Android VPN. No claim of physical-device acceptance.
 */
internal class RootZapret2(private val context: Context) : RootDpiRuntime {
    // Snapshot options at connection startup; mid-session preference changes
    // require reconnect so watchdog and firewall agree on the active rules.
    private val rootQuic = AppPrefs(context).zapret2RootQuic
    private val lifecycle = RootLifecycleTransaction(
        ROOT, lockDirectory = RootLifecycleTransaction.SHARED_LOCK_DIRECTORY,
        peerDirectory = RootLifecycleTransaction.BYEDPI_DIRECTORY,
    )

    override suspend fun start(): Result<Unit> = withContext(Dispatchers.IO) {
        runCatching {
            // Read-only preflight, only after explicit selection of ROOT.
            execute(RootDpiPreflight.script(RootDpiPreflight.Kind.PACKET))
            val abi = Build.SUPPORTED_ABIS.firstOrNull { it in ARCH }
                ?: error("nfqws2 не собран для архитектуры устройства")
            val hosts = Zapret2Hostlist.parse(AppPrefs(context).zapret2HostlistText).getOrThrow()
            val stage = File(context.noBackupFilesDir, "zapret2-stage").apply { mkdirs() }
            val binary = stageAsset("zapret2/" + abi + "/nfqws2", File(stage, "nfqws2"))
            val lua = LUA.map { stageAsset("zapret2/lua/" + it, File(stage, it)) }
            val hostsFile = File(stage, "hosts.txt").apply { writeText(hosts.format() + "\n") }
            val owner = RootOwnerIdentity(android.os.Process.myPid(), RootProcessIdentity.currentAppStartTime())
            val helper = RootPidfdDeployment.stage(context)
            try {
                val startup = lifecycle.start(cleanup(), launch(binary, lua, hostsFile, hosts.isEmpty, owner, helper), owner,
                    preservePreviousOwner = true, prepare = helper?.install(ROOT) ?: ":")
                rootLaunchWithRollback(
                    launch = { execute(startup) },
                    rollback = { execute(lifecycle.stop(cleanup())) },
                )
            } finally {
                helper?.discard()
            }
        }
    }

    /** Cleanup result must not be silently discarded when firewall rules remain. */
    override suspend fun stop(): Result<Unit> = withContext(Dispatchers.IO) {
        runCatching { execute(lifecycle.stop(cleanup())) }
    }

    override suspend fun alive(): Boolean = withContext(Dispatchers.IO) {
        runCatching { execute(lifecycle.alive(RootProcessIdentity.executableAlive(ROOT + "/pid", ROOT + "/nfqws2") +
            " && iptables -t mangle -C OUTPUT " + TCP +
            (if (rootQuic) " && iptables -t mangle -C OUTPUT " + UDP else ""))) }.isSuccess
    }

    private fun stageAsset(name: String, target: File): File {
        context.assets.open(name).use { input ->
            target.outputStream().use { output -> input.copyTo(output) }
        }
        return target
    }

    private fun launch(bin: File, lua: List<File>, hostsFile: File, allHosts: Boolean, owner: RootOwnerIdentity,
                       helper: RootPidfdDeployment.Staged?): String {
        val command = quote(ROOT + "/nfqws2") + Zapret2RootProfiles.arguments(allHosts, rootQuic)
        val parts = mutableListOf(
            "set -eu",
            "umask 077",
            "mkdir -p " + quote(ROOT),
            "chmod 700 " + quote(ROOT),
            if (helper != null) RootPidfdCleanup.requireForLaunch(ROOT) else ":",
            "cp " + quote(bin.absolutePath) + " " + quote(ROOT + "/nfqws2"),
            "chmod 700 " + quote(ROOT + "/nfqws2"),
        )
        lua.forEach { parts += "cp " + quote(it.absolutePath) + " " + quote(ROOT + "/" + it.name) }
        parts += "cp " + quote(hostsFile.absolutePath) + " " + quote(ROOT + "/hosts.txt")
        parts += listOf(
            "cd " + quote(ROOT),
            RootProcessIdentity.detachedCommand(command, ROOT + "/nfqws.log"),
            "pid=$!",
            "echo \"\$pid\" > " + quote(ROOT + "/pid"),
            "sleep 1",
            RootProcessIdentity.executableAlive("$ROOT/pid", "$ROOT/nfqws2"),
            lifecycle.captureExecutable("pid", "$ROOT/nfqws2"),

        )
        // A root-owned watchdog removes our NFQUEUE hooks after force-stop or
        // process crash. An Android app cannot rely on onDestroy in that case.
        val watchdogScript = lifecycle.watchdog(RootProcessIdentity.watchdogCondition(
            owner.pid, owner.startTime, "$ROOT/pid", "$ROOT/nfqws2",
        ), cleanup(stopWatch = false))
        parts += listOf(
            "cat > " + quote(ROOT + "/watchdog.sh") +
                " <<'DPPASS_WATCHDOG'\n#!/system/bin/sh\n" + watchdogScript + "\nDPPASS_WATCHDOG",
            "chmod 700 " + quote(ROOT + "/watchdog.sh"),
            RootProcessIdentity.detachedCommand("sh " + quote(ROOT + "/watchdog.sh"), ROOT + "/watchdog.log"),
            "echo \"\$!\" > " + quote(ROOT + "/watch.pid"),
            lifecycle.captureWatchdog("$ROOT/watchdog.sh"),
        )
        parts += listOf(
            // Listener first, firewall second. Queue bypass prevents a traffic blackout.
            "iptables -t mangle -I OUTPUT " + TCP,
            "iptables -t mangle -C OUTPUT " + TCP,
            *(if (rootQuic) arrayOf("iptables -t mangle -I OUTPUT " + UDP, "iptables -t mangle -C OUTPUT " + UDP) else emptyArray()),
            "if command -v ip6tables >/dev/null 2>&1; then",
            RootFirewallCleanup.markIntent("$ROOT/ipv6.intent"),
            "ip6tables -t mangle -I OUTPUT " + TCP,
            "ip6tables -t mangle -C OUTPUT " + TCP,
            *(if (rootQuic) arrayOf("ip6tables -t mangle -I OUTPUT " + UDP, "ip6tables -t mangle -C OUTPUT " + UDP) else emptyArray()),
            "fi",
        )
        return parts.joinToString("\n")
    }

    private fun cleanup(stopWatch: Boolean = true): String = buildString {
        appendLine("set +e")
        appendLine(RootFirewallCleanup.remove(RootFirewallCleanup.Kind.PACKET, "iptables", listOf(TCP, UDP)))
        appendLine(RootFirewallCleanup.remove(RootFirewallCleanup.Kind.PACKET, "ip6tables", listOf(TCP, UDP),
            optional = true, intentFile = "$ROOT/ipv6.intent"))
        if (stopWatch) appendLine(RootPidfdCleanup.stopWatchdog(ROOT, "$ROOT/watchdog.sh"))
        appendLine(RootPidfdCleanup.stopExecutable(ROOT, "pid", "$ROOT/nfqws2"))
        appendLine("exit 0")
    }

    private fun execute(script: String) {
        val result = RootCommandRunner.run(listOf("su", "-c", script))
        check(result.exitCode == 0) { "su / nfqws2 / iptables: " + result.outputTail }
    }

    private fun quote(raw: String): String = "'" + raw.replace("'", "'\\''") + "'"

    private companion object {
        const val ROOT = RootLifecycleTransaction.ZAPRET_DIRECTORY
        const val TCP = "-p tcp -m mark ! --mark 0x40000000/0x40000000 -m multiport --dports 80,443 -j NFQUEUE --queue-num 20529 --queue-bypass"
        const val UDP = "-p udp -m mark ! --mark 0x40000000/0x40000000 --dport 443 -j NFQUEUE --queue-num 20529 --queue-bypass"
        val ARCH = setOf("arm64-v8a", "armeabi-v7a", "x86_64")
        val LUA = listOf("zapret-lib.lua", "zapret-antidpi.lua", "zapret-auto.lua", "zapret-obfs.lua")
    }
}
