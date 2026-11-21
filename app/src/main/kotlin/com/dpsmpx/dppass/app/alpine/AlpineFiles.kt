package com.dpsmpx.dppass.app.alpine

import android.content.Context
import android.net.ConnectivityManager
import android.os.Build
import android.system.Os
import java.io.File
import java.io.FileOutputStream
import java.io.IOException
import java.io.InputStream
import java.security.MessageDigest
import java.util.zip.GZIPInputStream

/**
 * Verified Alpine minirootfs installer adapted from DPmetaApp's RootfsInstaller.
 * Install once in private storage; never write outside a fresh staging rootfs
 * or through symlinks. Ready marker is written only after complete extraction.
 * This is an application-UID PRoot, not a privileged Linux container.
 */
internal object AlpineFiles {
    private const val VERSION = "3.24.3"
    private const val ASSET = "alpine/rootfs.tgz"
    private const val SHA256 = "4d3f80afaebd447c5591a63a73bde380a149fe8b2d85488cafabb2ff97551f50"
    private const val BLOCK = 512
    private const val MAX_ENTRY = 64L * 1024 * 1024
    private const val MAX_TOTAL = 512L * 1024 * 1024
    private const val MAX_META = 64L * 1024

    fun layout(context: Context): AlpineArgs.Layout {
        val root = File(context.filesDir, "alpine/$VERSION/rootfs")
        val native = File(context.applicationInfo.nativeLibraryDir)
        return AlpineArgs.Layout(
            proot = File(native, "libproot.so").path,
            loader = File(native, "libproot-loader.so").path,
            rootfs = root.path,
            tmp = File(context.cacheDir, "alpine-proot-tmp").apply { mkdirs() }.path,
        )
    }

    fun supported(context: Context): Boolean {
        val l = layout(context)
        return Build.SUPPORTED_ABIS.contains("arm64-v8a") &&
            File(l.proot).isFile && File(l.loader).isFile
    }

    fun installed(context: Context): Boolean =
        File(layout(context).rootfs, ".dppass-alpine-ready").isFile

    @Synchronized
    fun install(context: Context) {
        check(supported(context)) { "Alpine runtime was not bundled; ARM64 and -Pdppass.alpine=true are required" }
        if (installed(context)) return
        // Two passes permit streaming extraction without an unverified archive.
        val digest = MessageDigest.getInstance("SHA-256")
        context.assets.open(ASSET).use { input ->
            val buf = ByteArray(32 * 1024)
            while (true) {
                val n = input.read(buf)
                if (n < 0) break
                digest.update(buf, 0, n)
            }
        }
        val actual = digest.digest().joinToString("") { "%02x".format(it) }
        check(actual == SHA256) { "Alpine minirootfs SHA-256 mismatch" }

        val finalRoot = File(layout(context).rootfs)
        val staged = File(finalRoot.parentFile, "rootfs.installing")
        check(staged.canonicalPath.startsWith(context.filesDir.canonicalPath + File.separator))
        if (staged.exists()) check(staged.deleteRecursively()) { "failed to clean interrupted rootfs installation" }
        check(staged.mkdirs())
        try {
            context.assets.open(ASSET).use { input -> unpack(GZIPInputStream(input.buffered()), staged) }
            // Install the same portable Zapret2 planner that Android's
            // protected-socket bridge uses. Executed under PRoot, not su.
            val runtime = File(staged, "usr/local/bin/dppass-zapret2")
            runtime.parentFile!!.mkdirs()
            context.assets.open("alpine/zapret2-runtime.bin").use { input ->
                FileOutputStream(runtime).use { out -> input.copyTo(out); out.fd.sync() }
            }
            Os.chmod(runtime.path, 493) // 0755
            // Keep canonical upstream Lua alongside the Alpine strategy
            // runtime for inspection and future Linux-backed packet adapters.
            val luaDir = File(staged, "opt/dppass/zapret2/lua").apply { mkdirs() }
            for (script in listOf("zapret-lib.lua", "zapret-antidpi.lua", "zapret-auto.lua", "zapret-obfs.lua")) {
                context.assets.open("zapret2/lua/$script").use { input ->
                    FileOutputStream(File(luaDir, script)).use { out -> input.copyTo(out); out.fd.sync() }
                }
            }
            // This ELF is an upstream Android nfqws2 executable for the root
            // adapter, NOT a general Alpine executable; it cannot obtain
            // NFQUEUE privileges inside the fake-root guest.
            val external = File(staged, "opt/dppass/zapret2/android").apply { mkdirs() }
            context.assets.open("zapret2/arm64-v8a/nfqws2").use { input ->
                FileOutputStream(File(external, "nfqws2")).use { out -> input.copyTo(out); out.fd.sync() }
            }
            File(staged, "root").mkdirs()
            File(staged, "tmp").mkdirs()
            val parent = finalRoot.parentFile ?: error("missing Alpine parent")
            parent.mkdirs()
            if (finalRoot.exists()) check(finalRoot.deleteRecursively()) { "failed to replace incomplete rootfs" }
            check(staged.renameTo(finalRoot)) { "failed to commit Alpine rootfs" }
            File(finalRoot, ".dppass-alpine-ready").writeText(VERSION)
        } catch (e: Exception) {
            staged.deleteRecursively()
            throw e
        }
    }

    /** Refresh only a regular guest file; do not follow a rootfs symlink. */
    fun refreshDns(context: Context) {
        if (!installed(context)) return
        val cm = context.getSystemService(ConnectivityManager::class.java)
        val servers = cm?.activeNetwork?.let { cm.getLinkProperties(it) }
            ?.dnsServers.orEmpty().mapNotNull { it.hostAddress }
        if (servers.isEmpty()) return
        val resolv = File(layout(context).rootfs, "etc/resolv.conf")
        if (!java.nio.file.Files.isSymbolicLink(resolv.toPath())) {
            resolv.parentFile?.mkdirs()
            resolv.writeText(servers.take(4).joinToString("\n") { "nameserver $it" } + "\n")
        }
    }

    private fun unpack(tar: InputStream, base: File) {
        val header = ByteArray(BLOCK)
        var total = 0L
        var longName: String? = null
        while (readHeader(tar, header)) {
            if (header.all { it.toInt() == 0 }) return
            val size = octal(header, 124, 12)
            val type = header[156].toInt().toChar()
            if (type in "Lxg") {
                check(size <= MAX_META) { "oversized tar extension" }
                val content = ByteArray(size.toInt())
                readExactly(tar, content)
                skipExactly(tar, pad(size))
                when (type) {
                    'L' -> longName = content.toString(Charsets.UTF_8).trimEnd('\u0000')
                    'x' -> longName = content.toString(Charsets.UTF_8)
                        .lineSequence().map { it.substringAfter(' ', "") }
                        .firstOrNull { it.startsWith("path=") }?.removePrefix("path=")
                }
                continue
            }
            val prefix = field(header, 345, 155)
            val name = longName ?: (if (prefix.isEmpty()) "" else "$prefix/") + field(header, 0, 100)
            longName = null
            val rel = name.removePrefix("./").trimEnd('/')
            val parts = rel.split('/')
            val safe = rel.isNotEmpty() && !rel.startsWith('/') && !rel.contains('\\') &&
                parts.all { it.isNotBlank() && it != "." && it != ".." }
            if (!safe || size > MAX_ENTRY) {
                skipExactly(tar, size + pad(size))
                continue
            }
            val path = File(base, rel)
            // Do not create anything through an archive-created symbolic link.
            var parent = path.parentFile
            var linked = false
            while (parent != null && parent != base) {
                if (java.nio.file.Files.isSymbolicLink(parent.toPath())) { linked = true; break }
                parent = parent.parentFile
            }
            if (linked || java.nio.file.Files.isSymbolicLink(path.toPath())) {
                skipExactly(tar, size + pad(size))
                continue
            }
            val mode = octal(header, 100, 8).toInt() and 511
            when (type) {
                '5' -> {
                    check(path.mkdirs() || path.isDirectory)
                    Os.chmod(path.path, mode)
                }
                '2' -> {
                    check(path.parentFile?.mkdirs() == true || path.parentFile?.isDirectory == true)
                    val link = field(header, 157, 100)
                    if (link.isNotEmpty()) Os.symlink(link, path.path)
                }
                '0', '\u0000', '7' -> {
                    total += size
                    check(total <= MAX_TOTAL) { "oversized rootfs" }
                    check(path.parentFile?.mkdirs() == true || path.parentFile?.isDirectory == true)
                    FileOutputStream(path).use { out ->
                        val b = ByteArray(8192)
                        var left = size
                        while (left > 0) {
                            val n = tar.read(b, 0, minOf(left, b.size.toLong()).toInt())
                            if (n <= 0) throw IOException("truncated Alpine tar")
                            out.write(b, 0, n)
                            left -= n
                        }
                        out.fd.sync()
                    }
                    Os.chmod(path.path, mode)
                    skipExactly(tar, pad(size))
                    continue
                }
                '1' -> {
                    val from = field(header, 157, 100).removePrefix("./")
                    // Alpine can contain hard links; copy only regular prior files.
                    val source = File(base, from)
                    val fromParts = from.split('/')
                    var sourceAncestor = base
                    val safeParents = fromParts.dropLast(1).all { piece ->
                        sourceAncestor = File(sourceAncestor, piece)
                        !java.nio.file.Files.isSymbolicLink(sourceAncestor.toPath())
                    }
                    if (fromParts.all { it.isNotEmpty() && it != ".." && it != "." } &&
                        !from.startsWith('/') && !from.contains('\\') &&
                        safeParents && source.isFile && !java.nio.file.Files.isSymbolicLink(source.toPath())) {
                        check(path.parentFile?.mkdirs() == true || path.parentFile?.isDirectory == true)
                        source.copyTo(path, overwrite = false)
                        Os.chmod(path.path, mode)
                        total += source.length()
                        check(total <= MAX_TOTAL)
                    }
                }
            }
            skipExactly(tar, size + pad(size))
        }
        throw IOException("Alpine archive missing tar end marker")
    }

    private fun readHeader(input: InputStream, header: ByteArray): Boolean {
        var done = 0
        while (done < header.size) {
            val n = input.read(header, done, header.size - done)
            if (n < 0) {
                if (done == 0) return false
                throw IOException("truncated tar header")
            }
            done += n
        }
        return true
    }

    private fun readExactly(input: InputStream, bytes: ByteArray) {
        var done = 0
        while (done < bytes.size) {
            val n = input.read(bytes, done, bytes.size - done)
            if (n <= 0) throw IOException("truncated Alpine metadata")
            done += n
        }
    }

    private fun skipExactly(input: InputStream, size: Long) {
        var left = size
        val b = ByteArray(8192)
        while (left > 0) {
            val n = input.read(b, 0, minOf(left, b.size.toLong()).toInt())
            if (n <= 0) throw IOException("truncated Alpine tar")
            left -= n
        }
    }

    private fun field(b: ByteArray, at: Int, size: Int): String {
        var end = at
        while (end < at + size && b[end].toInt() != 0) end++
        return String(b, at, end - at, Charsets.UTF_8)
    }

    private fun octal(b: ByteArray, at: Int, size: Int): Long =
        field(b, at, size).trim().ifEmpty { "0" }.toLongOrNull(8)?.takeIf { it >= 0 }
            ?: throw IOException("invalid tar size/mode")
    private fun pad(size: Long): Long = (BLOCK - size % BLOCK) % BLOCK
}
