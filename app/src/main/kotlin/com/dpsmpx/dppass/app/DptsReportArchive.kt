package com.dpsmpx.dppass.app

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.File
import java.nio.file.Files
import java.nio.file.LinkOption
import java.util.UUID

/** Explicitly saved snapshots only. Archived text cannot be restored as live evidence. */
internal class DptsReportArchive(private val directory: File) {
    data class Record(val id: String, val time: Long, val report: String, val csv: String?)

    private fun directoryReady(create: Boolean): Boolean {
        val path = directory.toPath()
        if (Files.notExists(path, LinkOption.NOFOLLOW_LINKS) && create) directory.mkdirs()
        return Files.isDirectory(path, LinkOption.NOFOLLOW_LINKS)
    }

    private fun paths(): List<File>? {
        if (Files.notExists(directory.toPath(), LinkOption.NOFOLLOW_LINKS)) return emptyList()
        if (!directoryReady(false)) return null
        return Files.newDirectoryStream(directory.toPath()).use { stream ->
            val files = mutableListOf<File>()
            for (path in stream) {
                if (!NAME.matches(path.fileName.toString())) continue
                if (files.size == MAX_RECORDS) return null
                files += path.toFile()
            }
            files
        }
    }

    private fun decode(file: File): Record? {
        if (!NAME.matches(file.name) || !Files.isRegularFile(file.toPath(), LinkOption.NOFOLLOW_LINKS)) return null
        val raw = ModelSnapshotFile.readBounded(file, MAX_RECORD_BYTES) ?: return null
        return runCatching {
            DataInputStream(ByteArrayInputStream(raw)).use { input ->
                require(input.readInt() == MAGIC)
                val time = input.readLong()
                require(time > 0)
                fun field(nullable: Boolean): String? {
                    val count = input.readInt()
                    if (nullable && count == -1) return null
                    require(count in 1..MAX_FIELD_BYTES && count <= input.available())
                    val bytes = ByteArray(count)
                    input.readFully(bytes)
                    return bytes.decodeToString(throwOnInvalidSequence = true)
                }
                val report = requireNotNull(field(false))
                val csv = field(true)
                require(input.available() == 0 && report.isNotBlank())
                Record(file.name.removeSuffix(".report"), time, report, csv)
            }
        }.getOrNull()
    }

    fun list(): List<Record>? = synchronized(lock) {
        runCatching {
            paths()?.mapNotNull(::decode)?.sortedWith(compareByDescending<Record> { it.time }.thenBy { it.id })
        }.getOrNull()
    }

    fun save(report: String, csv: String?, time: Long = System.currentTimeMillis()): Boolean = synchronized(lock) {
        runCatching {
            if (report.isBlank() || time <= 0 || report.length > MAX_FIELD_BYTES ||
                (csv != null && (csv.isBlank() || csv.length > MAX_FIELD_BYTES))) return@synchronized false
            val text = report.encodeToByteArray()
            val matrix = csv?.encodeToByteArray()
            if (text.size !in 1..MAX_FIELD_BYTES || (matrix != null && matrix.size !in 1..MAX_FIELD_BYTES)) return@synchronized false
            if (!directoryReady(true) || (paths()?.size ?: MAX_RECORDS) >= MAX_RECORDS) return@synchronized false
            val id = UUID.randomUUID().toString()
            val destination = File(directory, "$id.report")
            if (!Files.notExists(destination.toPath(), LinkOption.NOFOLLOW_LINKS)) return@synchronized false
            val out = ByteArrayOutputStream()
            DataOutputStream(out).use { data ->
                data.writeInt(MAGIC)
                data.writeLong(time)
                data.writeInt(text.size)
                data.write(text)
                data.writeInt(matrix?.size ?: -1)
                matrix?.let { data.write(it) }
            }
            ModelSnapshotFile.replace(destination, out.toByteArray())
        }.getOrDefault(false)
    }

    fun delete(record: Record): Boolean = synchronized(lock) {
        runCatching {
            val name = record.id + ".report"
            if (!NAME.matches(name) || !directoryReady(false)) return@synchronized false
            val file = File(directory, name)
            decode(file) == record && Files.deleteIfExists(file.toPath())
        }.getOrDefault(false)
    }

    companion object {
        const val MAX_RECORDS = 20
        const val MAX_FIELD_BYTES = 128 * 1024
        private const val MAX_RECORD_BYTES = 20 + 2 * MAX_FIELD_BYTES
        private const val MAGIC = 0x44505231 // DPR1
        private val NAME = Regex("[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\\.report")
        private val lock = Any()
    }
}
