package com.dpsmpx.dppass.app.alpine

import android.content.Context
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.LinkOption
import java.nio.file.SimpleFileVisitor
import java.nio.file.FileVisitResult
import java.nio.file.attribute.BasicFileAttributes
import java.security.MessageDigest

/** Private, atomic install from the SHA-256-pinned APK asset. */
internal object AlpineInstaller {
    const val VERSION = "alpine-minirootfs-3.24.3"
    private const val PIN = "4d3f80afaebd447c5591a63a73bde380a149fe8b2d85488cafabb2ff97551f50"

    fun installed(home: File): Boolean =
        File(home, "ready").takeIf { it.isFile }?.readText()?.trim() == VERSION &&
            Files.exists(File(home, "rootfs/bin/sh").toPath(), LinkOption.NOFOLLOW_LINKS) &&
            Files.exists(File(home, "rootfs/bin/busybox").toPath(), LinkOption.NOFOLLOW_LINKS)

    @Synchronized
    fun install(context: Context, home: File): Boolean {
        if (installed(home)) return false
        home.mkdirs()
        val ready = File(home, "ready")
        require(!ready.exists()) { "Alpine rootfs has an incompatible version; it will not be overwritten" }
        val downloaded = File(context.cacheDir, "dppass-alpine-archive.tgz")
        val stage = File(home, "rootfs-staging")
        val root = File(home, "rootfs")
        deleteTree(stage.toPath())
        try {
            val digest = MessageDigest.getInstance("SHA-256")
            context.assets.open("alpine/rootfs.tgz").use { input ->
                FileOutputStream(downloaded).use { output ->
                    val b = ByteArray(8192)
                    while (true) {
                        val n = input.read(b)
                        if (n < 0) break
                        digest.update(b, 0, n)
                        output.write(b, 0, n)
                    }
                    output.fd.sync()
                }
            }
            val actual = digest.digest().joinToString("") { "%02x".format(it) }
            require(actual == PIN) { "Alpine rootfs SHA-256 mismatch" }
            FileInputStream(downloaded).use { AlpineTar.unpack(it, stage.toPath()) }
            require(!root.exists()) { "Unmarked Alpine rootfs already exists; refusing to overwrite" }
            require(stage.renameTo(root)) { "Could not atomically activate Alpine rootfs" }
            val draft = File(home, "ready.tmp")
            FileOutputStream(draft).use { out ->
                out.write((VERSION + "\n").toByteArray(Charsets.UTF_8))
                out.fd.sync()
            }
            require(draft.renameTo(ready)) { "Could not activate Alpine version marker" }
            return true
        } catch (e: Exception) {
            deleteTree(stage.toPath())
            throw e
        } finally {
            downloaded.delete()
        }
    }

    /** Never follows guest-created symlinks during failed-install cleanup. */
    private fun deleteTree(root: Path) {
        if (!Files.exists(root)) return
        Files.walkFileTree(root, object : SimpleFileVisitor<Path>() {
            override fun visitFile(file: Path, attrs: BasicFileAttributes): FileVisitResult {
                Files.deleteIfExists(file)
                return FileVisitResult.CONTINUE
            }

            override fun postVisitDirectory(dir: Path, error: java.io.IOException?): FileVisitResult {
                if (error != null) throw error
                Files.deleteIfExists(dir)
                return FileVisitResult.CONTINUE
            }
        })
    }
}
