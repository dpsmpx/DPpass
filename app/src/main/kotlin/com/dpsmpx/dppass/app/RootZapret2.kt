package com.dpsmpx.dppass.app

import android.content.Context
import android.os.Build
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
    suspend fun start(): Result<Unit> = withContext(Dispatchers.IO) {
        runCatching {
            val abi = Build.SUPPORTED_ABIS.firstOrNull { it in ARCH }
                ?: error("nfqws2 не собран для архитектуры устройства")
            val stage = File(context.noBackupFilesDir, "zapret2-stage").apply { mkdirs() }
            val binary = stageAsset("zapret2/" + abi + "/nfqws2", File(stage, "nfqws2"))
            val lua = LUA.map { stageAsset("zapret2/lua/" + it, File(stage, it)) }
            execute(cleanup())
            try {
                execute(launch(binary, lua))
            } catch (e: Exception) {
                runCatching { execute(cleanup()) }
                throw e
            }
        }
    }

    suspend fun stop() = withContext(Dispatchers.IO) {
        runCatching { execute(cleanup()) }
        Unit
    }

    suspend fun alive(): Boolean = withContext(Dispatchers.IO) {
        runCatching { execute("test -f " + quote(ROOT + "/pid") +
            " && kill -0 \"$(cat " + quote(ROOT + "/pid") + ")\"") }.isSuccess
    }

    private fun stageAsset(name: String, target: File): File {
        context.assets.open(name).use { input ->
            target.outputStream().use { output -> input.copyTo(output) }
        }
        return target
    }

    private fun launch(bin: File, lua: List<File>): String {
        val parts = mutableListOf(
            "set -eu",
            "umask 077",
            "mkdir -p " + quote(ROOT),
            "chmod 700 " + quote(ROOT),
            "cp " + quote(bin.absolutePath) + " " + quote(ROOT + "/nfqws2"),
            "chmod 700 " + quote(ROOT + "/nfqws2"),
        )
        lua.forEach { parts += "cp " + quote(it.absolutePath) + " " + quote(ROOT + "/" + it.name) }
        parts += listOf(
            "cd " + quote(ROOT),
            quote(ROOT + "/nfqws2") + " --qnum=20529" +
                " --lua-init=@zapret-lib.lua --lua-init=@zapret-antidpi.lua" +
                " --filter-tcp=80 --filter-l7=http --payload=http_req" +
                " --lua-desync=fake:blob=fake_default_http:tcp_md5" +
                " --lua-desync=multisplit:pos=method+2 --new" +
                " --filter-tcp=443 --filter-l7=tls --payload=tls_client_hello" +
                " --lua-desync=fake:blob=fake_default_tls:tcp_md5:tcp_seq=-10000" +
                " --lua-desync=multidisorder:pos=1,midsld --new" +
                " --filter-udp=443 --filter-l7=quic --payload=quic_initial" +
                " --lua-desync=fake:blob=fake_default_quic:repeats=6" +
                " > " + quote(ROOT + "/nfqws.log") + " 2>&1 &",
            "pid=$!",
            "sleep 1",
            "kill -0 \"$pid\"",
            "echo \"$pid\" > " + quote(ROOT + "/pid"),
            // Listener first, firewall second. Queue bypass prevents a traffic blackout.
            "iptables -t mangle -I OUTPUT " + TCP,
            "iptables -t mangle -I OUTPUT " + UDP,
            "if command -v ip6tables >/dev/null 2>&1; then " +
                "ip6tables -t mangle -I OUTPUT " + TCP + "; ip6tables -t mangle -I OUTPUT " + UDP + "; fi",
        )
        return parts.joinToString("\n")
    }

    private fun cleanup(): String = listOf(
        "set +e",
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
    ).joinToString("\n")

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
        const val TCP = "-p tcp -m multiport --dports 80,443 -j NFQUEUE --queue-num 20529 --queue-bypass"
        const val UDP = "-p udp --dport 443 -j NFQUEUE --queue-num 20529 --queue-bypass"
        val ARCH = setOf("arm64-v8a", "armeabi-v7a", "x86_64")
        val LUA = listOf("zapret-lib.lua", "zapret-antidpi.lua", "zapret-auto.lua", "zapret-obfs.lua")
    }
}
