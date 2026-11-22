package com.dpsmpx.dppass.app

import android.content.Context
import java.io.File
import java.security.SecureRandom
import kotlin.math.sqrt
import org.json.JSONArray
import org.json.JSONObject

/**
 * Local-only, opt-in neural model generation. No pretrained weights, model
 * archive, downloader or external inference endpoint are used.
 *
 * The generated files contain ONLY numeric weights. Never persist URLs,
 * server IDs, user traffic, app identities or samples in these files.
 */
object Zapret2NeuralModel {
    enum class Kind(val filename: String, val format: String, val outputs: Int) {
        STRATEGY("strategy-v2.json", "dppass-zapret2-mlp-v2", 9),
        SERVER("server-v1.json", "dppass-server-mlp-v1", 1),
    }

    /** 128 is a balanced default; 512/1024 are explicit opt-in larger models. */
    val SIZES: List<Int> = listOf(32, 128, 512, 1024)
    const val DEFAULT_HIDDEN = 128
    const val MAX_BYTES = 1_048_576
    private const val INPUTS = 8
    private const val DIRECTORY = "local-models"
    private val random = SecureRandom()

    private fun file(context: Context, kind: Kind) =
        File(File(context.filesDir, DIRECTORY), kind.filename)

    private fun gaussianWeight(fanIn: Int): Double =
        (random.nextGaussian() * (0.10 / sqrt(fanIn.toDouble())))
            .coerceIn(-0.25, 0.25)

    /**
     * Uses balanced random initialization, NOT a claimed pretrained model.
     * On-device observations provide the subsequent optimization.
     * Array dimensions/values are revalidated by native Go before use.
     */
    fun build(kind: Kind, hidden: Int): ByteArray {
        require(hidden in SIZES) { "Unsupported model size" }
        fun vector(size: Int, fanIn: Int): JSONArray = JSONArray().also { row ->
            repeat(size) { row.put(gaussianWeight(fanIn)) }
        }
        val hiddenRows = JSONArray()
        repeat(hidden) { hiddenRows.put(vector(INPUTS, INPUTS)) }
        val outputRows = JSONArray()
        repeat(kind.outputs) { outputRows.put(vector(hidden, hidden)) }
        val obj = JSONObject()
            .put("format", kind.format)
            .put("hidden", hiddenRows)
            .put("bias", JSONArray().apply { repeat(hidden) { put(0.0) } })
            .put("output", outputRows)
            .put("output_bias", JSONArray().apply { repeat(kind.outputs) { put(0.0) } })
        return obj.toString().encodeToByteArray().also {
            check(it.size <= MAX_BYTES) { "Model exceeds 1 MiB memory/disk budget" }
        }
    }

    /** Fast structural verification of persisted weights; no URL or network. */
    fun verify(raw: ByteArray, kind: Kind): Boolean {
        if (raw.isEmpty() || raw.size > MAX_BYTES) return false
        return runCatching {
            val obj = JSONObject(raw.decodeToString())
            if (obj.getString("format") != kind.format) return@runCatching false
            val h = obj.getJSONArray("hidden")
            val b = obj.getJSONArray("bias")
            val o = obj.getJSONArray("output")
            val ob = obj.getJSONArray("output_bias")
            if (h.length() !in SIZES || b.length() != h.length() ||
                o.length() != kind.outputs || ob.length() != kind.outputs) return@runCatching false
            fun valid(row: JSONArray, count: Int): Boolean {
                if (row.length() != count) return false
                for (i in 0 until row.length()) {
                    val v = row.getDouble(i)
                    if (!v.isFinite() || kotlin.math.abs(v) > 4) return false
                }
                return true
            }
            valid(b, h.length()) && valid(ob, kind.outputs) &&
                (0 until h.length()).all { valid(h.getJSONArray(it), INPUTS) } &&
                (0 until kind.outputs).all { valid(o.getJSONArray(it), h.length()) }
        }.getOrDefault(false)
    }

    fun readVerified(context: Context, kind: Kind = Kind.STRATEGY): ByteArray? {
        val source = file(context, kind)
        if (!source.isFile || source.length() !in 1L..MAX_BYTES.toLong()) return null
        return runCatching { source.readBytes().takeIf { verify(it, kind) } }.getOrNull()
    }

    fun size(context: Context, kind: Kind = Kind.STRATEGY): Int? =
        readVerified(context, kind)?.let { raw ->
            runCatching { JSONObject(raw.decodeToString()).getJSONArray("hidden").length() }.getOrNull()
        }

    fun isInstalled(context: Context, kind: Kind = Kind.STRATEGY): Boolean =
        readVerified(context, kind) != null

    /** A single atomic local-file replace; no download or network access. */
    fun store(context: Context, kind: Kind, raw: ByteArray): Boolean {
        if (!verify(raw, kind)) return false
        val dest = file(context, kind)
        val dir = dest.parentFile ?: return false
        if (!dir.isDirectory && !dir.mkdirs()) return false
        val temp = File(dir, kind.filename + ".pending")
        return try {
            temp.writeBytes(raw)
            if (!temp.renameTo(dest)) error("Atomic model replace failed")
            true
        } finally {
            temp.delete()
        }
    }

    /** Called on Dispatchers.Default/IO after explicit user action. */
    fun generate(context: Context, kind: Kind, hidden: Int): Result<ByteArray> = runCatching {
        val raw = build(kind, hidden)
        check(store(context, kind, raw)) { "Failed to store generated model" }
        raw
    }

    fun delete(context: Context, kind: Kind = Kind.STRATEGY): Boolean {
        val model = file(context, kind)
        return !model.exists() || model.delete()
    }
}
