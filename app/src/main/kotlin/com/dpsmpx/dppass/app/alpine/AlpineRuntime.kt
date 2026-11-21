package com.dpsmpx.dppass.app.alpine

import android.content.Context
import android.net.ConnectivityManager
import android.os.Build
import java.io.File
import java.nio.file.Files

/**
 * DP_IDE's Alpine/PRoot launch model, isolated from DPpass's VPN engine.
 * The guest shares the app UID: fake root does not grant CAP_NET_ADMIN,
 * raw sockets, NFQUEUE, or access to Android iptables.
 */
internal object AlpineRuntime {
    private val devices = listOf(
        "/dev/null", "/dev/zero", "/dev/full", "/dev/random",
        "/dev/urandom", "/dev/tty", "/dev/ptmx", "/dev/pts",
    )

    fun available(context: Context): Boolean {
        val lib = File(context.applicationInfo.nativeLibraryDir)
        return Build.SUPPORTED_ABIS.contains("arm64-v8a") &&
            File(lib, "libproot.so").isFile &&
            File(lib, "libproot-loader.so").isFile &&
            File(lib, "libdppass-alpine.so").isFile
    }

    fun root(context: Context): File = File(context.noBackupFilesDir, "alpine")

    fun installed(context: Context): Boolean = AlpineInstaller.installed(root(context))

    fun install(context: Context): Boolean {
        check(available(context)) { "Alpine/PRoot доступен только в arm64-v8a APK" }
        return AlpineInstaller.install(context, root(context))
    }

    /** DNS is rewritten atomically and never follows guest symlinks. */
    fun refreshDns(context: Context) {
        val cm = context.getSystemService(ConnectivityManager::class.java) ?: return
        val addresses = cm.activeNetwork?.let(cm::getLinkProperties)?.dnsServers.orEmpty()
            .mapNotNull { it.hostAddress?.substringBefore('%') }
            .filter { it.contains('.') || it.contains(':') }
            .distinct().take(3)
        if (addresses.isEmpty()) return
        val etc = File(File(root(context), "rootfs"), "etc")
        if (Files.isSymbolicLink(etc.toPath()) || !etc.isDirectory) return
        val draft = File(root(context), "resolv.conf.draft")
        draft.writeText(addresses.joinToString(separator = "\n", postfix = "\n") { "nameserver " + it })
        if (!draft.renameTo(File(etc, "resolv.conf"))) draft.delete()
    }

    /**
     * apk-tools 3 must run WITHOUT binding /proc (DP_IDE D-82):
     * O_TMPFILE/linkat via /proc/self/fd would fail under Android's
     * hardlink restrictions. Every argument is an independent argv item.
     */
    fun runPackages(context: Context, action: String, packageNames: String): Pair<Int, String> {
        check(installed(context)) { "Сначала установите Alpine" }
        check(available(context)) { "Alpine/PRoot доступен только на ARM64" }
        val guest = AlpinePackageCommand.arguments(action, packageNames)
        refreshDns(context)
        val lib = File(context.applicationInfo.nativeLibraryDir)
        val tmp = File(context.cacheDir, "alpine-tmp").apply { mkdirs() }
        val args = listOf(
            File(lib, "libproot.so").absolutePath,
            "--kill-on-exit", "--link2symlink", "-0", "-r",
            File(root(context), "rootfs").absolutePath,
            "-b", "/dev/null", "-b", "/dev/zero", "-b", "/dev/random",
            "-b", "/dev/urandom",
            "-w", "/root",
        ) + guest
        val environment = mutableMapOf(
            "HOME" to "/root",
            "PATH" to "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            "LANG" to "C.UTF-8",
            "TMPDIR" to "/tmp",
            "PROOT_LOADER" to File(lib, "libproot-loader.so").absolutePath,
            "PROOT_TMP_DIR" to tmp.absolutePath,
        )
        val process = ProcessBuilder(args)
            .directory(context.filesDir)
            .redirectErrorStream(true)
            .apply { environment().clear(); environment().putAll(environment) }
            .start()
        val out = StringBuilder()
        try {
            process.inputStream.bufferedReader().use { input ->
                val buf = CharArray(2048)
                while (true) {
                    val n = input.read(buf)
                    if (n < 0) break
                    out.append(buf, 0, n)
                    if (out.length > 24_000) out.delete(0, out.length - 24_000)
                }
            }
            val code = process.waitFor()
            return code to out.toString()
        } finally {
            if (process.isAlive) process.destroyForcibly()
        }
    }

    fun shell(context: Context, cols: Int, rows: Int): AlpineChild {
        require(installed(context)) { "Сначала установите Alpine" }
        check(available(context)) { "Нет исполняемого PRoot для устройства" }
        refreshDns(context)
        val lib = File(context.applicationInfo.nativeLibraryDir)
        val tmp = File(context.cacheDir, "alpine-tmp").apply { mkdirs() }
        val home = root(context)
        val args = buildList {
            add(File(lib, "libproot.so").absolutePath)
            add("--kill-on-exit")
            add("--link2symlink")
            add("-0")
            add("-r")
            add(File(home, "rootfs").absolutePath)
            for (device in devices) {
                if (File(device).exists()) {
                    add("-b")
                    add(device)
                }
            }
            add("-b")
            add("/proc")
            for ((from, to) in listOf(
                "/proc/self/fd" to "/dev/fd",
                "/proc/self/fd/0" to "/dev/stdin",
                "/proc/self/fd/1" to "/dev/stdout",
                "/proc/self/fd/2" to "/dev/stderr",
            )) {
                add("-b")
                add(from + ":" + to)
            }
            add("-w")
            add("/root")
            add("/bin/sh")
            add("-l")
        }
        val env = mapOf(
            "HOME" to "/root",
            "PATH" to "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            "LANG" to "C.UTF-8",
            "TERM" to "xterm-256color",
            "COLORTERM" to "truecolor",
            "TMPDIR" to "/tmp",
            "PROOT_LOADER" to File(lib, "libproot-loader.so").absolutePath,
            "PROOT_TMP_DIR" to tmp.absolutePath,
        )
        return AlpineChild.launch(args, env, cols, rows)
    }
}
