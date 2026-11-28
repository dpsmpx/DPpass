package com.dpsmpx.dppass.app

import java.io.File
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.nio.file.attribute.BasicFileAttributes
import java.security.MessageDigest

/** Called under the model storage lock. No migration or arbitrary path deletion. */
internal object ObsoleteModelFiles {
    private const val MAX_BYTES = 1_048_576
    private const val MAX_FILES = 64
    private val pendingName = Regex("\\.model-[0-9-]+\\.pending")
    private val retiredServer = setOf("dppass-server-mlp-v1", "dppass-server-mlp-v2", "dppass-server-mlp-v3")
    enum class Reason { RETIRED_STRATEGY, RETIRED_SERVER, PENDING }
    data class Entry(val name: String, val bytes: Long, val reason: Reason, internal val sha256: String)
    data class Result(val changed: Boolean, val removed: List<Entry> = emptyList(), val failed: List<Entry> = emptyList())

    private fun candidate(name: String): Boolean =
        name == "strategy-v2.json" || name == "server-v1.json" || pendingName.matches(name)

    private fun attrs(path: Path): BasicFileAttributes =
        Files.readAttributes(path, BasicFileAttributes::class.java, LinkOption.NOFOLLOW_LINKS)

    private fun entry(path: Path): Entry? {
        val name = path.fileName.toString()
        if (!candidate(name)) return null
        val before = attrs(path)
        if (!before.isRegularFile || before.size() !in 0L..MAX_BYTES.toLong()) return null
        val raw = Files.newInputStream(path, LinkOption.NOFOLLOW_LINKS).use { input ->
            val output = java.io.ByteArrayOutputStream()
            val buffer = ByteArray(8192)
            while (true) {
                val count = input.read(buffer)
                if (count < 0) break
                if (count == 0 || count > MAX_BYTES - output.size()) return null
                output.write(buffer, 0, count)
            }
            output.toByteArray()
        }
        val after = attrs(path)
        if (!after.isRegularFile || before.fileKey() != after.fileKey() ||
            before.lastModifiedTime() != after.lastModifiedTime() ||
            before.size() != after.size() || raw.size.toLong() != after.size()) return null
        val reason = when {
            name == "strategy-v2.json" -> {
                // This exact filename is retired; do not delete a current
                // or unknown-format model that happens to use that name.
                val format = ModelJsonPreflight.format(raw, MAX_BYTES) ?: return null
                if (!Regex("dppass-strategy-mlp-v[1-4](:[A-Za-z0-9=,;_-]+)?").matches(format) &&
                    format !in setOf("dppass-zapret2-mlp-v2", "dppass-zapret2-mlp-v3")) return null
                Reason.RETIRED_STRATEGY
            }
            name == "server-v1.json" -> {
                // The current server model still uses this filename.
                if (ModelJsonPreflight.format(raw, MAX_BYTES) !in retiredServer) return null
                Reason.RETIRED_SERVER
            }
            else -> Reason.PENDING
        }
        val digest = MessageDigest.getInstance("SHA-256").digest(raw).joinToString("") { "%02x".format(it) }
        return Entry(name, after.size(), reason, digest)
    }

    fun scan(directory: File): List<Entry>? {
        return try {
            val root = directory.toPath()
            if (Files.notExists(root, LinkOption.NOFOLLOW_LINKS)) emptyList()
            else if (!Files.isDirectory(root, LinkOption.NOFOLLOW_LINKS)) null
            else Files.newDirectoryStream(root).use { paths ->
                val result = mutableListOf<Entry>()
                var candidates = 0
                for (path in paths) {
                    if (!candidate(path.fileName.toString())) continue
                    if (++candidates > MAX_FILES) return null
                    entry(path)?.let(result::add)
                }
                result.sortedBy { it.name }
            }
        } catch (_: Exception) { null }
    }

    fun clean(directory: File, expected: List<Entry>): Result {
        val current = scan(directory)
        if (current == null || current != expected) return Result(changed = true)
        val removed = mutableListOf<Entry>()
        val failed = mutableListOf<Entry>()
        for (item in current) {
            val path = directory.toPath().resolve(item.name)
            // Recheck each file immediately before deleting; no path
            // comes from user input, and symlinks are never followed.
            val ok = runCatching {
                Files.isDirectory(directory.toPath(), LinkOption.NOFOLLOW_LINKS) &&
                    entry(path) == item && Files.deleteIfExists(path)
            }.getOrDefault(false)
            if (ok) removed += item else failed += item
        }
        return Result(false, removed, failed)
    }
}
