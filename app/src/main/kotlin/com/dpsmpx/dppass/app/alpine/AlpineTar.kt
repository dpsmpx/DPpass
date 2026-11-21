package com.dpsmpx.dppass.app.alpine

import java.io.EOFException
import java.io.IOException
import java.io.InputStream
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.nio.file.Paths
import java.nio.file.attribute.PosixFilePermission
import java.util.zip.GZIPInputStream

/**
 * Bounded, traversal-safe Alpine minirootfs extractor adapted from DP_IDE's
 * RootfsInstaller. Never resolves symlink ancestors while writing the archive.
 */
internal object AlpineTar {
    private const val BLOCK = 512
    private const val MAX_FILE = 64L * 1024 * 1024
    private const val MAX_TOTAL = 512L * 1024 * 1024
    private const val MAX_META = 64L * 1024

    data class Summary(val files: Int, val directories: Int, val symlinks: Int, val bytes: Long)

    fun unpack(gzip: InputStream, root: Path): Summary {
        Files.createDirectories(root)
        val base = root.toAbsolutePath().normalize()
        var files = 0
        var dirs = 0
        var links = 0
        var total = 0L
        var longName: String? = null
        GZIPInputStream(gzip.buffered()).use { tar ->
            while (true) {
                val h = readHeader(tar) ?: break
                if (h.all { it == 0.toByte() }) break
                val size = octal(h, 124, 12)
                if (size > MAX_TOTAL) throw IOException("Alpine archive entry exceeds size limit")
                val type = h[156].toInt().toChar()
                if (type == 'L' || type == 'x' || type == 'g') {
                    if (size > MAX_META) throw IOException("Alpine archive metadata is too large")
                    val meta = readExactly(tar, size.toInt()).toString(Charsets.UTF_8)
                    skip(tar, padding(size))
                    if (type == 'L') longName = meta.trimEnd('\u0000', '\n')
                    if (type == 'x') {
                        val p = meta.lineSequence().map { it.substringAfter(' ', "") }
                            .firstOrNull { it.startsWith("path=") }
                        if (p != null) longName = p.removePrefix("path=")
                    }
                    continue
                }
                val prefix = string(h, 345, 155)
                val name = longName ?: ((if (prefix.isEmpty()) "" else prefix + "/") + string(h, 0, 100))
                longName = null
                val rel = name.removePrefix("./").trimEnd('/')
                val dest = resolveSafe(base, rel)
                if (dest == null || unsafeParent(base, dest.parent)) {
                    skip(tar, size + padding(size))
                    continue
                }
                val mode = octal(h, 100, 8).toInt() and 511
                when (type) {
                    '5' -> {
                        Files.createDirectories(dest)
                        permissions(dest, mode)
                        dirs++
                        skip(tar, size + padding(size))
                    }
                    '2' -> {
                        Files.createDirectories(dest.parent)
                        Files.deleteIfExists(dest)
                        // The link text is interpreted inside guest PRoot.
                        Files.createSymbolicLink(dest, Paths.get(string(h, 157, 100)))
                        links++
                        skip(tar, size + padding(size))
                    }
                    '1' -> {
                        val source = resolveSafe(base, string(h, 157, 100).removePrefix("./"))
                        if (source != null && !unsafeParent(base, source.parent) &&
                            Files.isRegularFile(source, LinkOption.NOFOLLOW_LINKS)) {
                            val length = Files.size(source)
                            total += length
                            if (total > MAX_TOTAL) throw IOException("Alpine rootfs exceeds 512 MiB")
                            Files.createDirectories(dest.parent)
                            Files.deleteIfExists(dest)
                            Files.copy(source, dest)
                            permissions(dest, mode)
                            files++
                        }
                        skip(tar, size + padding(size))
                    }
                    '0', '\u0000', '7' -> {
                        if (size > MAX_FILE) throw IOException("Alpine regular file exceeds 64 MiB")
                        total += size
                        if (total > MAX_TOTAL) throw IOException("Alpine rootfs exceeds 512 MiB")
                        Files.createDirectories(dest.parent)
                        Files.deleteIfExists(dest)
                        Files.newOutputStream(dest).use { out ->
                            var remaining = size
                            val buffer = ByteArray(8192)
                            while (remaining > 0) {
                                val n = tar.read(buffer, 0, minOf(buffer.size.toLong(), remaining).toInt())
                                if (n < 0) throw EOFException("Truncated Alpine file")
                                out.write(buffer, 0, n)
                                remaining -= n
                            }
                        }
                        permissions(dest, mode)
                        files++
                        skip(tar, padding(size))
                    }
                    else -> skip(tar, size + padding(size))
                }
            }
        }
        if (files == 0 || !Files.exists(base.resolve("bin/sh"), LinkOption.NOFOLLOW_LINKS)) {
            throw IOException("Alpine rootfs is incomplete: missing /bin/sh")
        }
        return Summary(files, dirs, links, total)
    }

    /** Returns null for absolute, dot-segment, or escaped archive paths. */
    fun resolveSafe(base: Path, name: String): Path? {
        if (name.isEmpty() || name.startsWith('/') || name.contains('\\')) return null
        val parts = name.split('/')
        if (parts.any { it == ".." || it == "." || it.isEmpty() }) return null
        val normalized = base.resolve(name).normalize()
        return normalized.takeIf { it.startsWith(base) && it != base }
    }

    private fun unsafeParent(base: Path, parent: Path): Boolean {
        if (!parent.startsWith(base)) return true
        var p = base
        for (name in base.relativize(parent)) {
            p = p.resolve(name)
            if (Files.isSymbolicLink(p)) return true
        }
        return false
    }

    private fun permissions(path: Path, mode: Int) {
        val names = listOf(
            PosixFilePermission.OWNER_READ to 256, PosixFilePermission.OWNER_WRITE to 128,
            PosixFilePermission.OWNER_EXECUTE to 64, PosixFilePermission.GROUP_READ to 32,
            PosixFilePermission.GROUP_WRITE to 16, PosixFilePermission.GROUP_EXECUTE to 8,
            PosixFilePermission.OTHERS_READ to 4, PosixFilePermission.OTHERS_WRITE to 2,
            PosixFilePermission.OTHERS_EXECUTE to 1,
        )
        Files.setPosixFilePermissions(path, names.filter { (mode and it.second) != 0 }.mapTo(mutableSetOf()) { it.first })
    }

    private fun readHeader(input: InputStream): ByteArray? {
        val h = ByteArray(BLOCK)
        var off = 0
        while (off < BLOCK) {
            val n = input.read(h, off, BLOCK - off)
            if (n < 0) {
                if (off == 0) return null
                throw EOFException("Truncated Alpine tar header")
            }
            if (n == 0) continue
            off += n
        }
        return h
    }

    private fun readExactly(input: InputStream, length: Int): ByteArray {
        val result = ByteArray(length)
        var off = 0
        while (off < length) {
            val n = input.read(result, off, length - off)
            if (n < 0) throw EOFException("Truncated Alpine tar payload")
            if (n == 0) continue
            off += n
        }
        return result
    }

    private fun string(h: ByteArray, offset: Int, length: Int): String {
        var end = offset
        while (end < offset + length && h[end] != 0.toByte()) end++
        return String(h, offset, end - offset, Charsets.UTF_8)
    }

    private fun octal(h: ByteArray, offset: Int, length: Int): Long {
        val n = string(h, offset, length).trim()
        return if (n.isEmpty()) 0L else n.toLongOrNull(8)?.takeIf { it >= 0 }
            ?: throw IOException("Invalid Alpine tar header")
    }

    private fun padding(bytes: Long): Long = (BLOCK - bytes % BLOCK) % BLOCK

    private fun skip(input: InputStream, count: Long) {
        val buffer = ByteArray(8192)
        var left = count
        while (left > 0) {
            val n = input.read(buffer, 0, minOf(buffer.size.toLong(), left).toInt())
            if (n < 0) throw EOFException("Truncated Alpine tar")
            if (n == 0) continue
            left -= n
        }
    }
}
