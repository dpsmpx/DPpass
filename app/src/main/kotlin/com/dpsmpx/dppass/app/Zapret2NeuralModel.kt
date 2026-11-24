package com.dpsmpx.dppass.app

import android.content.Context
import java.io.File
import java.security.SecureRandom
import kotlin.math.sqrt
import org.json.JSONArray
import org.json.JSONObject

/**
 * On-device MLP with optional sparse, lazily materialized parameter capacity.
 * A 100M budget does NOT allocate 100M Doubles: the dense 1–2-layer core
 * remains bounded, while only the sparse weights touched by training are
 * stored. Network/transport-specific heads keep their observations separately.
 * No subscription addresses, raw traffic, model downloads or remote AI.
 */
object Zapret2NeuralModel {
    enum class Kind(
        val filename: String, val format: String,
        val legacyFormat: String, val outputs: Int, val contexts: Int,
    ) {
        STRATEGY("strategy-v2.json", "dppass-zapret2-mlp-v3", "dppass-zapret2-mlp-v2", 9, 9),
        SERVER("server-v1.json", "dppass-server-mlp-v2", "dppass-server-mlp-v1", 1, 6),
    }

    val SIZES: List<Int> = listOf(32, 128, 512, 1024)
    const val DEFAULT_HIDDEN = 128
    const val MAX_BYTES = 1_048_576
    const val MAX_PARAMETERS = 1_000_000_000L
    const val MAX_SPARSE_ENTRIES = 4096
    private const val INPUTS = 8
    private const val DIRECTORY = "local-models"
    private val random = SecureRandom()
    private val storageGuard = Any()

    private fun file(context: Context, kind: Kind) =
        File(File(context.filesDir, DIRECTORY), kind.filename)

    private fun gaussianWeight(fanIn: Int): Double =
        (random.nextGaussian() * (0.10 / sqrt(fanIn.toDouble())))
            .coerceIn(-0.25, 0.25)

    private fun vector(size: Int, fanIn: Int): JSONArray = JSONArray().also { row ->
        repeat(size) { row.put(gaussianWeight(fanIn)) }
    }

    /** Exact count of trainable dense weights and scenario-head biases. */
    private fun denseCount(kind: Kind, first: Int, second: Int): Long {
        val last = if (second > 0) second else first
        return first.toLong() * (INPUTS + 1) +
            (if (second > 0) second.toLong() * (first + 1) else 0L) +
            kind.outputs.toLong() * (last + 1) +
            kind.contexts.toLong() * kind.outputs
    }

    fun minParameters(kind: Kind): Long = denseCount(kind, 8, 0)

    /**
     * Auto-design: bounded one layer on small budgets and two layers for
     * larger ones, to avoid interactive VPN inference latency and OOMs.
     * Remaining requested capacity is available as sparse hashed weights.
     */
    fun architecture(kind: Kind, parameters: Long): Pair<Int, Int> {
        require(parameters in minParameters(kind)..MAX_PARAMETERS) { "Unsupported parameter budget" }
        if (parameters >= 1_000_000) return 128 to 64
        if (parameters >= 50_000) return 96 to 48
        val maxFirst = (parameters - kind.outputs -
            kind.contexts.toLong() * kind.outputs) / (INPUTS + 1 + kind.outputs)
        return maxFirst.coerceIn(8L, 128L).toInt() to 0
    }

    private fun create(kind: Kind, first: Int, second: Int, budget: Long): ByteArray {
        require(first in 8..1024 && second in 0..512)
        require(budget in denseCount(kind, first, second)..MAX_PARAMETERS)
        val hidden = JSONArray().also { rows ->
            repeat(first) { rows.put(vector(INPUTS, INPUTS)) }
        }
        val deep = JSONArray().also { rows ->
            repeat(second) { rows.put(vector(first, first)) }
        }
        val output = JSONArray().also { rows ->
            repeat(kind.outputs) { rows.put(vector(if (second > 0) second else first,
                if (second > 0) second else first)) }
        }
        val obj = JSONObject()
            .put("format", kind.format)
            .put("parameters", budget)
            .put("seed", java.lang.Long.toHexString(random.nextLong()).padStart(16, '0'))
            .put("hidden", hidden)
            .put("bias", JSONArray().apply { repeat(first) { put(0.0) } })
            .put("deep_hidden", deep)
            .put("deep_bias", JSONArray().apply { repeat(second) { put(0.0) } })
            .put("output", output)
            .put("output_bias", JSONArray().apply { repeat(kind.outputs) { put(0.0) } })
            .put("context_bias", JSONArray().apply {
                repeat(kind.contexts) {
                    put(JSONArray().apply { repeat(kind.outputs) { put(0.0) } })
                }
            })
            .put("context_observations", JSONArray().apply { repeat(kind.contexts) { put(0) } })
            .put("sparse", JSONObject())
            .put("observations", 0)
        return obj.toString().encodeToByteArray().also {
            check(it.size <= MAX_BYTES) { "Generated dense model exceeds 1 MiB" }
        }
    }

    /** Back-compatible preset sizes, now with durable contextual heads. */
    fun build(kind: Kind, hidden: Int): ByteArray {
        require(hidden in SIZES) { "Unsupported hidden size" }
        return create(kind, hidden, 0, denseCount(kind, hidden, 0))
    }

    /** A requested 100,000,000 is a 100M-slot trainable budget, not RAM use. */
    fun buildParameters(kind: Kind, parameters: Long): ByteArray {
        val (first, second) = architecture(kind, parameters)
        return create(kind, first, second, parameters)
    }

    private fun validNumber(value: Double): Boolean = value.isFinite() && kotlin.math.abs(value) <= 4.0

    /** Independent bounded validation before storage, then repeated in Go. */
    fun verify(raw: ByteArray, kind: Kind): Boolean {
        if (raw.isEmpty() || raw.size > MAX_BYTES) return false
        return runCatching {
            val obj = JSONObject(raw.decodeToString())
            val format = obj.getString("format")
            val modern = format == kind.format
            if (!modern && format != kind.legacyFormat) return@runCatching false
            val h = obj.getJSONArray("hidden")
            val b = obj.getJSONArray("bias")
            val o = obj.getJSONArray("output")
            val ob = obj.getJSONArray("output_bias")
            if (h.length() !in 8..1024 || b.length() != h.length() ||
                o.length() != kind.outputs || ob.length() != kind.outputs ||
                !modern && h.length() !in SIZES) return@runCatching false
            fun valid(row: JSONArray, count: Int): Boolean {
                if (row.length() != count) return false
                for (i in 0 until count) if (!validNumber(row.getDouble(i))) return false
                return true
            }
            if (!valid(b, h.length()) || !valid(ob, kind.outputs) ||
                !(0 until h.length()).all { valid(h.getJSONArray(it), INPUTS) })
                return@runCatching false
            val deep = if (modern) obj.getJSONArray("deep_hidden") else JSONArray()
            val deepBias = if (modern) obj.getJSONArray("deep_bias") else JSONArray()
            if (deep.length() > 512 || deepBias.length() != deep.length() ||
                !valid(deepBias, deep.length()) ||
                !(0 until deep.length()).all { valid(deep.getJSONArray(it), h.length()) })
                return@runCatching false
            val last = if (deep.length() > 0) deep.length() else h.length()
            if (!(0 until kind.outputs).all { valid(o.getJSONArray(it), last) })
                return@runCatching false
            if (!modern) return@runCatching true
            val budget = obj.getLong("parameters")
            val used = denseCount(kind, h.length(), deep.length())
            if (budget !in used..MAX_PARAMETERS ||
                !obj.getString("seed").matches(Regex("[0-9a-f]{16}")))
                return@runCatching false
            val context = obj.getJSONArray("context_bias")
            val counts = obj.getJSONArray("context_observations")
            if (context.length() != kind.contexts || counts.length() != kind.contexts ||
                !(0 until kind.contexts).all { i ->
                    valid(context.getJSONArray(i), kind.outputs) &&
                        counts.getLong(i) in 0L..1_000_000_000L
                }) return@runCatching false
            // The optional, fixed 3×6 HTML calibration is separate from the
            // legacy MLP parameter budget. Older snapshots need no migration.
            if (obj.has("verified_html_bias") || obj.has("verified_html_observations")) {
                if (kind != Kind.STRATEGY) return@runCatching false
                val html = obj.getJSONArray("verified_html_bias")
                val htmlCounts = obj.getJSONArray("verified_html_observations")
                if (html.length() != 3 || htmlCounts.length() != 3 ||
                    !(0 until 3).all { i ->
                        valid(html.getJSONArray(i), 6) &&
                            htmlCounts.getLong(i) in 0L..1_000_000_000L
                    }) return@runCatching false
            }
            val sparse = obj.getJSONObject("sparse")
            if (sparse.length() > MAX_SPARSE_ENTRIES) return@runCatching false
            val capacity = budget - used
            for (key in sparse.keys()) {
                val index = key.toLongOrNull() ?: return@runCatching false
                if (index !in 0L until capacity || !validNumber(sparse.getDouble(key)))
                    return@runCatching false
            }
            obj.optLong("observations", 0) in 0L..1_000_000_000L
        }.getOrDefault(false)
    }

    private fun migrateLegacy(kind: Kind, raw: ByteArray): ByteArray {
        val model = JSONObject(raw.decodeToString())
        if (model.getString("format") == kind.format) return raw
        val hidden = model.getJSONArray("hidden").length()
        model.put("format", kind.format)
        model.put("parameters", denseCount(kind, hidden, 0))
        model.put("seed", java.lang.Long.toHexString(random.nextLong()).padStart(16, '0'))
        model.put("deep_hidden", JSONArray())
        model.put("deep_bias", JSONArray())
        model.put("context_bias", JSONArray().apply {
            repeat(kind.contexts) {
                put(JSONArray().apply { repeat(kind.outputs) { put(0.0) } })
            }
        })
        model.put("context_observations", JSONArray().apply { repeat(kind.contexts) { put(0) } })
        model.put("sparse", JSONObject())
        // Original numeric weights and global observation count survive.
        // Unknown past network conditions are not misattributed to any head.
        if (!model.has("observations")) model.put("observations", 0)
        return model.toString().encodeToByteArray().also { check(verify(it, kind)) }
    }

    fun readVerified(context: Context, kind: Kind = Kind.STRATEGY): ByteArray? =
        synchronized(storageGuard) {
            val source = file(context, kind)
            if (!source.isFile || source.length() !in 1L..MAX_BYTES.toLong()) return@synchronized null
            runCatching {
                val raw = source.readBytes().takeIf { verify(it, kind) }
                    ?: return@runCatching null
                val modern = migrateLegacy(kind, raw)
                if (!modern.contentEquals(raw)) {
                    if (!write(context, kind, modern)) return@runCatching raw
                }
                modern
            }.getOrNull()
        }

    fun size(context: Context, kind: Kind = Kind.STRATEGY): Int? =
        readVerified(context, kind)?.let { raw ->
            runCatching { JSONObject(raw.decodeToString()).getJSONArray("hidden").length() }.getOrNull()
        }

    fun parameters(context: Context, kind: Kind = Kind.STRATEGY): Long? =
        readVerified(context, kind)?.let { raw ->
            runCatching {
                val obj = JSONObject(raw.decodeToString())
                if (obj.getString("format") == kind.format) obj.getLong("parameters")
                else null
            }.getOrNull()
        }

    fun isInstalled(context: Context, kind: Kind = Kind.STRATEGY) =
        readVerified(context, kind) != null

    private fun write(context: Context, kind: Kind, raw: ByteArray): Boolean {
        val dest = file(context, kind)
        val dir = dest.parentFile ?: return false
        if (!dir.isDirectory && !dir.mkdirs()) return false
        val temp = File(dir, kind.filename + ".pending")
        return try {
            temp.writeBytes(raw)
            if (!temp.renameTo(dest)) error("Atomic replace failed")
            true
        } finally {
            temp.delete()
        }
    }

    fun store(context: Context, kind: Kind, raw: ByteArray): Boolean =
        synchronized(storageGuard) { verify(raw, kind) && write(context, kind, raw) }

    /**
     * JNI snapshots must not overwrite a user-regenerated model. The seed
     * identifies the immutable architecture, whereas learned weights differ.
     */
    fun storeLearnedSnapshot(context: Context, kind: Kind, raw: ByteArray): Boolean =
        synchronized(storageGuard) {
            if (!verify(raw, kind)) return@synchronized false
            val now = readVerified(context, kind) ?: return@synchronized false
            val latest = JSONObject(now.decodeToString())
            val snapshot = JSONObject(raw.decodeToString())
            if (latest.optString("format") != kind.format ||
                snapshot.optString("format") != kind.format ||
                latest.optString("seed") != snapshot.optString("seed"))
                return@synchronized false
            write(context, kind, raw)
        }

    fun generate(context: Context, kind: Kind, hidden: Int): Result<ByteArray> = runCatching {
        build(kind, hidden).also { check(store(context, kind, it)) }
    }

    fun generateParameters(context: Context, kind: Kind, parameters: Long): Result<ByteArray> =
        runCatching { buildParameters(kind, parameters).also { check(store(context, kind, it)) } }

    fun delete(context: Context, kind: Kind = Kind.STRATEGY): Boolean =
        synchronized(storageGuard) {
            val model = file(context, kind)
            !model.exists() || model.delete()
        }
}
