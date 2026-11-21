package com.dpsmpx.dppass.app

import android.content.Context
import android.os.Build
import com.dpsmpx.dppass.connection.Zapret2Hostlist
import com.dpsmpx.dppass.connection.Zapret2RootProfiles
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.File
import java.util.concurrent.TimeUnit

/**
 * Experimental rooted Zapret2 adapter. Requires su, iptables NFQUEUE target,
 * a kernel that supports NFQUEUE, and execution allowed under /data/adb.
 * Does not establish Android VPN. No claim of physical-device acceptance.
 */
internal class RootZapret2(private val context: Context) {
    // Snapshot options at connection startup; mid-session preference changes
    // require reconnect so watchdog and firewall agree on the active rules.
    private val rootQuic = AppPrefs(context).zapret2RootQuic

    suspend fun start(): Result<Unit> = withContext(Dispatchers.IO) {
        runCatching {
            val abi = Build.SUPPORTED_ABIS.firstOrNull { it in ARCH }
                ?: error("nfqws2 не собран для архитектуры устройства")
            val hosts = Zapret2Hostlist.parse(AppPrefs(context).zapret2HostlistText).getOrThrow()
            val stage = File(context.noBackupFilesDir, "zapret2-stage").apply { mkdirs() }
            val binary = stageAsset("zapret2/" + abi + "/nfqws2", File(stage, "nfqws2"))
            val lua = LUA.map { stageAsset("zapret2/lua/" + it, File(stage, it)) }
            val hostsFile = File(stage, "hosts.txt").apply { writeText(hosts.format() + "\n") }
            execute(cleanup())
            try {
                execute(launch(binary, lua, hostsFile, hosts.isEmpty))
            } catch (e: Exception) {
                runCatching { execute(cleanup()) }
                throw e
            }
        }
    }

    /** Cleanup result must not be silently discarded when firewall rules remain. */
    suspend fun stop(): Result<Unit> = withContext(Dispatchers.IO) {
        runCatching { execute(cleanup()) }
    }

    suspend fun alive(): Boolean = withContext(Dispatchers.IO) {
        runCatching { execute("test -f " + quote(ROOT + "/pid") +
            " && kill -0 \"$(cat " + quote(ROOT + "/pid") + ")\"" +
            " && iptables -t mangle -C OUTPUT " + TCP +
            (if (rootQuic) " && iptables -t mangle -C OUTPUT " + UDP else "")) }.isSuccess
    }

    private fun stageAsset(name: String, target: File): File {
        context.assets.open(name).use { input ->
            target.outputStream().use { output -> input.copyTo(output) }
        }
        return target
    }

    private fun launch(bin: File, lua: List<File>, hostsFile: File, allHosts: Boolean): String {
        val command = quote(ROOT + "/nfqws2") + Zapret2RootProfiles.arguments(allHosts, rootQuic)
        val parts = mutableListOf(
            "set -eu",
            "umask 077",
            "mkdir -p " + quote(ROOT),
            "chmod 700 " + quote(ROOT),
            "cp " + quote(bin.absolutePath) + " " + quote(ROOT + "/nfqws2"),
            "chmod 700 " + quote(ROOT + "/nfqws2"),
        )
        lua.forEach { parts += "cp " + quote(it.absolutePath) + " " + quote(ROOT + "/" + it.name) }
        parts += "cp " + quote(hostsFile.absolutePath) + " " + quote(ROOT + "/hosts.txt")
        parts += listOf(
            "cd " + quote(ROOT),
            command + " > " + quote(ROOT + "/nfqws.log") + " 2>&1 &",
            "pid=$!",
            "sleep 1",
            "kill -0 \"\$pid\"",
            "echo \"\$pid\" > " + quote(ROOT + "/pid"),
            // Listener first, firewall second. Queue bypass prevents a traffic blackout.
            "iptables -t mangle -I OUTPUT " + TCP,
            *(if (rootQuic) arrayOf("iptables -t mangle -I OUTPUT " + UDP) else emptyArray()),
            "if command -v ip6tables >/dev/null 2>&1; then " +
                "ip6tables -t mangle -I OUTPUT " + TCP +
                (if (rootQuic) "; ip6tables -t mangle -I OUTPUT " + UDP else "") + "; fi",
        )
        // A root-owned watchdog removes our NFQUEUE hooks after force-stop or
        // process crash. An Android app cannot rely on onDestroy in that case.
        val watchdogScript = "while kill -0 " + android.os.Process.myPid() +
            " 2>/dev/null; do sleep 3; done\n" + cleanup(stopWatch = false)
        parts += listOf(
            "cat > " + quote(ROOT + "/watchdog.sh") +
                " <<'DPPASS_WATCHDOG'\n#!/system/bin/sh\n" + watchdogScript + "\nDPPASS_WATCHDOG",
            "chmod 700 " + quote(ROOT + "/watchdog.sh"),
            "sh " + quote(ROOT + "/watchdog.sh") + " < /dev/null > " +
                quote(ROOT + "/watchdog.log") + " 2>&1 &",
            "echo \"\$!\" > " + quote(ROOT + "/watch.pid"),
        )
        return parts.joinToString("\n")
    }

    private fun cleanup(stopWatch: Boolean = true): String = (
        listOf("set +e") +
            (if (stopWatch) listOf(
                "if test -f " + quote(ROOT + "/watch.pid") + "; then kill \"$(cat " +
                    quote(ROOT + "/watch.pid") + ")\" 2>/dev/null; rm -f " +
                    quote(ROOT + "/watch.pid") + "; fi",
            ) else emptyList()) +
            listOf(
        "while iptables -t mangle -C OUTPUT " + TCP +
            " 2>/dev/null; do iptables -t mangle -D OUTPUT " + TCP + " || break; done",
        "while iptables -t mangle -C OUTPUT " + UDP +
            " 2>/dev/null; do iptables -t mangle -D OUTPUT " + UDP + " || break; done",
        "if command -v ip6tables >/dev/null 2>&1; then " +
            "while ip6tables -t mangle -C OUTPUT " + TCP +
            " 2>/dev/null; do ip6tables -t mangle -D OUTPUT " + TCP + " || break; done; " +
            "while ip6tables -t mangle -C OUTPUT " + UDP +
            " 2>/dev/null; do ip6tables -t mangle -D OUTPUT " + UDP + " || break; done; fi",
        "if test -f " + quote(ROOT + "/pid") + "; then kill \"$(cat " +
            quote(ROOT + "/pid") + ")\" 2>/dev/null; rm -f " + quote(ROOT + "/pid") + "; fi",
        )).joinToString("\n")

    private fun execute(script: String) {
        val process = ProcessBuilder("su", "-c", script).redirectErrorStream(true).start()
        if (!process.waitFor(15, TimeUnit.SECONDS)) {
            process.destroyForcibly()
            error("su: timeout")
        }
        val output = process.inputStream.bufferedReader().use { it.readText().takeLast(400) }
        if (process.exitValue() != 0) error("su / nfqws2 / iptables: " + output)
    }

    private fun quote(raw: String): String = "'" + raw.replace("'", "'\\''") + "'"

    private companion object {
        const val ROOT = "/data/adb/dppass-zapret2"
        const val TCP = "-p tcp -m mark ! --mark 0x40000000/0x40000000 -m multiport --dports 80,443 -j NFQUEUE --queue-num 20529 --queue-bypass"
        const val UDP = "-p udp -m mark ! --mark 0x40000000/0x40000000 --dport 443 -j NFQUEUE --queue-num 20529 --queue-bypass"
        val ARCH = setOf("arm64-v8a", "armeabi-v7a", "x86_64")
        val LUA = listOf("zapret-lib.lua", "zapret-antidpi.lua", "zapret-auto.lua", "zapret-obfs.lua")
    }
}
