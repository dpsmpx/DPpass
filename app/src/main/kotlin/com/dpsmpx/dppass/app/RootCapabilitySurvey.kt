package com.dpsmpx.dppass.app

import java.util.concurrent.atomic.AtomicBoolean

/** Read-only observation, never an admission decision or firewall mutation. */
internal object RootCapabilitySurvey {
    data class Report(
        val netAdmin: Boolean,
        val netRaw: Boolean,
        val ipv4Nat: Boolean,
        val ipv4Mangle: Boolean,
        val ipv6Nat: Boolean,
        val ipv6Mangle: Boolean,
    )

    private val running = AtomicBoolean(false)

    fun script(): String = listOf(
        "test \"\$(id -u)\" = 0 || exit 1",
        "printf 'root_caps_v1\\n'",
        "cap=''",
        "while read -r key value rest; do case \"\$key\" in CapEff:) cap=\"\$value\"; break;; esac; done < /proc/\$\$/status",
        "printf 'cap=%s\\n' \"\$cap\"",
        "if iptables -t nat -S OUTPUT >/dev/null 2>&1; then echo v4nat=1; else echo v4nat=0; fi",
        "if iptables -t mangle -S OUTPUT >/dev/null 2>&1; then echo v4mangle=1; else echo v4mangle=0; fi",
        "if ip6tables -t nat -S OUTPUT >/dev/null 2>&1; then echo v6nat=1; else echo v6nat=0; fi",
        "if ip6tables -t mangle -S OUTPUT >/dev/null 2>&1; then echo v6mangle=1; else echo v6mangle=0; fi",
    ).joinToString("\n")

    fun parse(result: RootCommandRunner.CompleteResult): Report? {
        if (result.exitCode != 0 || result.stdout.length > 128 || !result.stdout.endsWith('\n')) return null
        val lines = result.stdout.dropLast(1).split('\n')
        if (lines.size != 6 || lines[0] != "root_caps_v1") return null
        val mask = lines[1].removePrefix("cap=")
        if (!lines[1].startsWith("cap=") || !mask.matches(Regex("[0-9a-fA-F]{16}"))) return null
        val low = mask.takeLast(8).toLongOrNull(16) ?: return null
        val keys = listOf("v4nat", "v4mangle", "v6nat", "v6mangle")
        val available = keys.mapIndexed { index, key ->
            when (lines[index + 2]) {
                "$key=1" -> true
                "$key=0" -> false
                else -> return null
            }
        }
        return Report(low and (1L shl 12) != 0L, low and (1L shl 13) != 0L,
            available[0], available[1], available[2], available[3])
    }

    fun run(command: (List<String>, Long) -> RootCommandRunner.CompleteResult =
        { args, timeout -> RootCommandRunner.runComplete(args, timeout) }): Report? {
        if (!running.compareAndSet(false, true)) return null
        return try {
            parse(command(listOf("su", "-c", script()), 15_000L))
        } catch (_: InterruptedException) {
            Thread.currentThread().interrupt()
            null
        } catch (_: Exception) {
            null
        } finally {
            running.set(false)
        }
    }
}
