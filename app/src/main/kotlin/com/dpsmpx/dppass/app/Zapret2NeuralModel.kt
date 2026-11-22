package com.dpsmpx.dppass.app

import android.content.Context
import java.io.ByteArrayOutputStream
import java.io.File
import java.net.URL
import java.security.MessageDigest
import javax.net.ssl.HttpsURLConnection

/**
 * Explicitly opt-in downloadable seed weights for the private Zapret2 MLP.
 * No weights are packaged in the APK. The URL is immutable (Git commit)
 * and the bytes are pinned by SHA-256; there is no model execution or
 * server-side inference, telemetry, dynamic code or arbitrary URL input.
 */
object Zapret2NeuralModel {
    const val MAX_BYTES = 4096
    const val EXPECTED_SHA256 =
        "a9172f287e6bd4e6ac6ce5cdc3a606cf125b3ec3a8041ebd9ba59b12ac6d7a2b"
    private const val URL =
        "https://raw.githubusercontent.com/dpsmpx/DPpass/" +
            "e754342d747819f4d1133b32b0426cf3c9354302/models/zapret2-mlp-seed-v1.json"
    private const val DIRECTORY = "zapret2-model"
    private const val FILENAME = "seed-v1.json"

    private fun file(context: Context): File = File(File(context.filesDir, DIRECTORY), FILENAME)

    private fun hex(bytes: ByteArray): String = bytes.joinToString("") { "%02x".format(it.toInt() and 255) }

    fun verify(bytes: ByteArray): Boolean =
        bytes.isNotEmpty() && bytes.size <= MAX_BYTES &&
            hex(MessageDigest.getInstance("SHA-256").digest(bytes)) == EXPECTED_SHA256

    /** Return only locally verified model bytes. Never make a network request. */
    fun readVerified(context: Context): ByteArray? {
        val target = file(context)
        if (!target.isFile || target.length() !in 1L..MAX_BYTES.toLong()) return null
        return runCatching {
            target.readBytes().takeIf(::verify)
        }.getOrNull()
    }

    fun isInstalled(context: Context): Boolean = readVerified(context) != null

    /** Called only from a user's explicit click, on Dispatchers.IO. */
    fun download(context: Context): Result<ByteArray> = runCatching {
        val connection = (URL(URL).openConnection() as HttpsURLConnection).apply {
            instanceFollowRedirects = false
            connectTimeout = 10_000
            readTimeout = 15_000
            requestMethod = "GET"
            setRequestProperty("Accept", "application/json")
        }
        val bytes = try {
            if (connection.responseCode != HttpsURLConnection.HTTP_OK) {
                error("HTTP ${connection.responseCode}; download rejected")
            }
            val len = connection.contentLengthLong
            if (len > MAX_BYTES) error("Model exceeds maximum size")
            connection.inputStream.use { input ->
                val buffer = ByteArray(1024)
                val output = ByteArrayOutputStream()
                while (true) {
                    val count = input.read(buffer)
                    if (count < 0) break
                    if (count == 0) continue
                    if (output.size() + count > MAX_BYTES) error("Model exceeds maximum size")
                    output.write(buffer, 0, count)
                }
                output.toByteArray()
            }
        } finally {
            connection.disconnect()
        }
        check(verify(bytes)) { "Downloaded model SHA-256 mismatch" }
        val dest = file(context)
        check(dest.parentFile?.isDirectory == true || dest.parentFile?.mkdirs() == true) {
            "Unable to create private model directory"
        }
        val temp = File(dest.parentFile, "${FILENAME}.pending")
        try {
            temp.writeBytes(bytes)
            check(temp.renameTo(dest)) { "Atomic model installation failed" }
        } finally {
            temp.delete()
        }
        bytes
    }

    fun delete(context: Context): Boolean {
        val model = file(context)
        return !model.exists() || model.delete()
    }
}
