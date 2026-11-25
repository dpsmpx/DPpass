package com.dpsmpx.dppass.app

import android.content.Context
import com.dpsmpx.dppass.config.TransportClass
import com.dpsmpx.dppass.config.transportClass
import com.dpsmpx.dppass.connection.ConnectionPlan
import com.dpsmpx.dppass.connection.ConnectionReport
import com.dpsmpx.dppass.connection.DPpassCore
import com.dpsmpx.dppass.connection.HealthState
import com.dpsmpx.dppass.network.NetworkType
import com.dpsmpx.dppass.diagnostics.Safe
import org.json.JSONArray
import org.json.JSONObject
import java.security.MessageDigest
import kotlin.math.exp
import kotlin.math.max
import kotlin.math.min

/**
 * Separate, locally generated and trained MLP for the "Automatically"
 * selection in the provider server list. Never invents a server, changes
 * user pins, bypasses eligibility/backoff, or accesses plaintext traffic.
 *
 * The existing CandidatePlanner remains authoritative for candidate
 * filtering, network restrictions, health, last-good and fallback.
 * ML may only swap neighboring candidates of the SAME health class
 * once sufficient local outcome evidence accumulates.
 */
object ServerAutoModel {
    private const val INPUTS = 8
    private const val LR = 0.035
    private val guard = Any()

    // A connection attempt needs its *pre-outcome* features to avoid
    // leaking the answer into the training sample. Kept only in RAM.
    private data class Pending(val features: DoubleArray, val scenario: Int)
    private var pending: Map<String, Pending> = emptyMap()
    private var pendingSize: Int = 0
    private var pendingDigest: String = ""

    private fun digest(bytes: ByteArray): String =
        MessageDigest.getInstance("SHA-256").digest(bytes)
            .joinToString("") { "%02x".format(it.toInt() and 0xff) }

    private fun features(core: DPpassCore, profile: com.dpsmpx.dppass.config.ServerProfile,
                         rank: Int, network: NetworkType, now: Long): DoubleArray {
        val health = core.health.of(profile.id)
        val latency = core.latency.millis(profile.id)
        val freshness = health.lastSuccessMillis?.let { previous ->
            1.0 / (1.0 + max(0L, now - previous).toDouble() / 3_600_000.0)
        } ?: 0.0
        return doubleArrayOf(
            latency?.let { 1.0 / (1.0 + it.coerceAtLeast(0).toDouble() / 300.0) } ?: 0.0,
            if (health.state == HealthState.HEALTHY) 1.0 else 0.0,
            min(1.0, health.consecutiveFailures.toDouble() / 5.0),
            if (core.health.lastGood() == profile.id) 1.0 else 0.0,
            freshness,
            if (profile.transportClass == TransportClass.UDP_QUIC) 1.0 else 0.0,
            if (network == NetworkType.MOBILE) 1.0 else 0.0,
            1.0 / (rank + 1.0),
        )
    }

    private fun scenario(profile: com.dpsmpx.dppass.config.ServerProfile,
                         network: NetworkType): Int {
        val n = when (network) {
            NetworkType.MOBILE -> 0
            NetworkType.WIFI -> 1
            else -> 2
        }
        return n * 2 + if (profile.transportClass == TransportClass.UDP_QUIC) 1 else 0
    }

    private fun modern(model: JSONObject): Boolean =
        model.optString("format") == Zapret2NeuralModel.Kind.SERVER.format

    private fun firstHidden(model: JSONObject, x: DoubleArray): DoubleArray {
        val matrix = model.getJSONArray("hidden")
        val bias = model.getJSONArray("bias")
        return DoubleArray(matrix.length()) { i ->
            val row = matrix.getJSONArray(i)
            var sum = bias.getDouble(i)
            for (j in 0 until INPUTS) sum += row.getDouble(j) * x[j]
            max(0.0, sum)
        }
    }

    private fun lastHidden(model: JSONObject, x: DoubleArray): DoubleArray {
        val first = firstHidden(model, x)
        val deeper = model.optJSONArray("deep_hidden") ?: return first
        if (deeper.length() == 0) return first
        val bias = model.getJSONArray("deep_bias")
        return DoubleArray(deeper.length()) { i ->
            val row = deeper.getJSONArray(i)
            var sum = bias.getDouble(i)
            for (j in first.indices) sum += row.getDouble(j) * first[j]
            max(0.0, sum)
        }
    }

    private fun sparseCapacity(model: JSONObject): Long {
        if (!modern(model)) return 0
        val h = model.getJSONArray("hidden").length()
        val deep = model.getJSONArray("deep_hidden").length()
        val last = if (deep > 0) deep else h
        val used = h.toLong() * (INPUTS + 1) +
            deep.toLong() * (h + 1) + last + 1L +
            Zapret2NeuralModel.Kind.SERVER.contexts
        return (model.getLong("parameters") - used).coerceAtLeast(0)
    }

    /** Stable keyed index; the JSON contains only numeric weights, never IDs. */
    private fun sparseKey(model: JSONObject, scenario: Int, profileId: String,
                          feature: Int, bucket: Int, capacity: Long): String {
        val seed = model.getString("seed")
        val data = "${seed}|${scenario}|${profileId}|${feature}|${bucket}"
        val hash = MessageDigest.getInstance("SHA-256").digest(data.encodeToByteArray())
        var n = 0L
        for (i in 0 until 7) n = (n shl 8) or (hash[i].toLong() and 255L)
        return (n % capacity).toString()
    }

    private fun forward(model: JSONObject, x: DoubleArray, scenario: Int,
                        profileId: String): Pair<Double, DoubleArray> {
        val hidden = lastHidden(model, x)
        val out = model.getJSONArray("output").getJSONArray(0)
        var z = model.getJSONArray("output_bias").getDouble(0)
        for (i in hidden.indices) z += out.getDouble(i) * hidden[i]
        if (modern(model)) {
            z += model.getJSONArray("context_bias").getJSONArray(scenario).getDouble(0)
            val capacity = sparseCapacity(model)
            if (capacity > 0) {
                val sparse = model.getJSONObject("sparse")
                for (i in x.indices) {
                    if (x[i] <= 0.0) continue
                    val bucket = (x[i] * 15.0).toInt().coerceIn(0, 15)
                    z += sparse.optDouble(sparseKey(model, scenario, profileId, i, bucket, capacity), 0.0) * x[i]
                }
            }
        }
        val probability = 1.0 / (1.0 + exp((-z).coerceIn(-12.0, 12.0)))
        return probability to hidden
    }

    /**
     * Never changes the candidate SET. Restrict to healthy/unknown pairs
     * and adjacent swaps; backoff failures retain planner placement.
     */
    fun rerank(context: Context, plan: ConnectionPlan, core: DPpassCore,
               network: NetworkType, now: Long): ConnectionPlan {
        val snapshot = Zapret2NeuralModel.readVerified(context, Zapret2NeuralModel.Kind.SERVER)
        if (snapshot == null || plan.attempts.size <= 1) {
            // No server identities, IP addresses or subscription URLs in logs.
            core.log.info("server_auto_model", "installed" to (snapshot != null),
                "candidates" to plan.attempts.size, "reordered" to 0)
            resetTransient()
            return plan
        }
        return runCatching {
            val model = JSONObject(snapshot.decodeToString())
            val observations = model.optInt("observations", 0)
            val scored = plan.attempts.mapIndexed { i, attempt ->
                val feat = features(core, attempt.profile, i, network, now)
                val scenario = scenario(attempt.profile, network)
                Triple(attempt, Pending(feat, scenario),
                    forward(model, feat, scenario, attempt.profile.id.value).first)
            }.toMutableList()
            synchronized(guard) {
                pending = scored.associate { it.first.profile.id.value to it.second }
                pendingSize = model.getJSONArray("hidden").length()
                pendingDigest = digest(snapshot)
            }
            // Existing planner rank is the safety prior. Neural evidence
            // must overcome an explicit margin, not random initialization.
            for (i in 0 until scored.lastIndex) {
                val left = scored[i]
                val right = scored[i + 1]
                val leftHealth = core.health.of(left.first.profile.id).state
                val rightHealth = core.health.of(right.first.profile.id).state
                val leftCount = if (modern(model))
                    model.getJSONArray("context_observations").getInt(left.second.scenario)
                    else observations
                val rightCount = if (modern(model))
                    model.getJSONArray("context_observations").getInt(right.second.scenario)
                    else observations
                if (leftHealth != rightHealth || leftHealth == HealthState.FAILED ||
                    leftCount < 4 || rightCount < 4) continue
                val advantage = right.third - left.third
                // Four real connection outcomes unlock a cautious, adjacent
                // same-health-class swap. Use a small but nonzero margin:
                // the generated MLP starts near 0.5 for all candidates.
                if (advantage > 0.003) {
                    scored[i] = right
                    scored[i + 1] = left
                }
            }
            val reordered = scored.indices.count { i ->
                scored[i].first.profile.id != plan.attempts[i].profile.id
            }
            core.log.info("server_auto_model", "installed" to true,
                "hidden" to model.getJSONArray("hidden").length(),
                "observations" to observations,
                "candidates" to plan.attempts.size,
                "reordered" to reordered)
            plan.copy(attempts = scored.map { it.first })
        }.getOrElse {
            resetTransient()
            plan
        }
    }

    private fun clamped(v: Double) = v.coerceIn(-4.0, 4.0)

    /** Train only on real orchestrator attempts after content health checks. */
    fun observe(context: Context, report: ConnectionReport, core: DPpassCore) {
        val (feats, expectedHidden, originalDigest) = synchronized(guard) {
            val copy = pending
            val size = pendingSize
            val previous = pendingDigest
            pending = emptyMap()
            pendingSize = 0
            pendingDigest = ""
            Triple(copy, size, previous)
        }
        if (feats.isEmpty()) {
            core.log.info("server_auto_learning", "trained" to 0, "persisted" to false)
            return
        }
        val raw = Zapret2NeuralModel.readVerified(context, Zapret2NeuralModel.Kind.SERVER)
        if (raw == null) {
            core.log.warning("server_auto_learning_failed", "reason" to Safe("model_not_found"))
            return
        }
        // A user may regenerate another model of the same width while
        // connecting. Never train stale features into replacement weights.
        if (digest(raw) != originalDigest) {
            core.log.info("server_auto_learning", "trained" to 0,
                "persisted" to false, "replaced" to true)
            return
        }
        runCatching {
            val model = JSONObject(raw.decodeToString())
            if (model.getJSONArray("hidden").length() != expectedHidden) {
                core.log.warning("server_auto_learning_failed", "reason" to Safe("model_width_changed"))
                return@runCatching
            }
            val hiddenRows = model.getJSONArray("hidden")
            val bias = model.getJSONArray("bias")
            val outputRows = model.getJSONArray("output")
            val output = outputRows.getJSONArray(0)
            val outBias = model.getJSONArray("output_bias")
            var learned = 0
            for (attempt in report.attempts) {
                val pendingAttempt = feats[attempt.profileId.value] ?: continue
                val x = pendingAttempt.features
                val scenario = pendingAttempt.scenario
                // Core-local/backend failures are not server failures.
                val failure = attempt.failure?.code?.name
                if (failure in setOf("BACKEND_ALREADY_RUNNING", "LOCAL_PROXY_UNAVAILABLE", "TUN_ESTABLISH_FAILED"))
                    continue
                val (p, h) = forward(model, x, scenario, attempt.profileId.value)
                val delta = LR * ((if (attempt.ok) 1.0 else 0.0) - p)
                learned++
                val oldWeights = DoubleArray(h.size) { output.getDouble(it) }
                for (i in h.indices) {
                    output.put(i, clamped(oldWeights[i] + delta * h[i]))
                }
                outBias.put(0, clamped(outBias.getDouble(0) + delta))
                val deep = model.optJSONArray("deep_hidden")
                if (deep != null && deep.length() > 0) {
                    // A second feature layer is updated using a smaller step;
                    // the shared first layer stays stable across scenarios.
                    val deepBias = model.getJSONArray("deep_bias")
                    val first = firstHidden(model, x)
                    for (i in h.indices) {
                        if (h[i] <= 0.0) continue
                        val scale = delta * oldWeights[i] * 0.1
                        val row = deep.getJSONArray(i)
                        deepBias.put(i, clamped(deepBias.getDouble(i) + scale))
                        for (j in first.indices)
                            row.put(j, clamped(row.getDouble(j) + scale * first[j]))
                    }
                } else {
                    for (i in h.indices) {
                        if (h[i] <= 0.0) continue
                        val scale = delta * oldWeights[i] * 0.1
                        val row = hiddenRows.getJSONArray(i)
                        bias.put(i, clamped(bias.getDouble(i) + scale))
                        for (j in 0 until INPUTS)
                            row.put(j, clamped(row.getDouble(j) + scale * x[j]))
                    }
                }
                if (modern(model)) {
                    // Independent LTE/Wi-Fi/other × TCP/QUIC heads prevent
                    // a failure in one context overwriting all other heads.
                    val head = model.getJSONArray("context_bias").getJSONArray(scenario)
                    head.put(0, clamped(head.getDouble(0) + delta))
                    val counts = model.getJSONArray("context_observations")
                    counts.put(scenario, ModelNumericFields.addObservations(counts.getLong(scenario), 1))
                    val capacity = sparseCapacity(model)
                    if (capacity > 0) {
                        val sparse = model.getJSONObject("sparse")
                        for (i in x.indices) {
                            if (x[i] <= 0.0) continue
                            val bucket = (x[i] * 15.0).toInt().coerceIn(0, 15)
                            val key = sparseKey(model, scenario, attempt.profileId.value,
                                i, bucket, capacity)
                            if (sparse.has(key) || sparse.length() < Zapret2NeuralModel.MAX_SPARSE_ENTRIES)
                                sparse.put(key, clamped(sparse.optDouble(key, 0.0) + delta * 0.2 * x[i]))
                        }
                    }
                }
            }
            if (learned == 0) {
                core.log.info("server_auto_learning", "trained" to 0, "persisted" to false)
                return@runCatching
            }
            model.put("observations", ModelNumericFields.addObservations(model.optLong("observations", 0), learned))
            // Revalidate and atomically persist only the numeric model,
            // not the server IDs or training examples.
            val persisted = Zapret2NeuralModel.storeIfUnchanged(
                context, Zapret2NeuralModel.Kind.SERVER, raw, model.toString().encodeToByteArray(),
            )
            core.log.info("server_auto_learning",
                "trained" to learned,
                "observations" to model.getInt("observations"),
                "persisted" to persisted)
            if (!persisted) core.log.warning("server_auto_learning_failed",
                "reason" to Safe("storage_or_stale_model"))
        }.onFailure {
            // Prior versions swallowed training failures, making a zero
            // observation count indistinguishable from a true cold start.
            core.log.warning("server_auto_learning_failed",
                "reason" to Safe("invalid_model_or_storage"))
        }
    }

    /** A network handoff changes the meaning of latency and failure data. */
    fun resetTransient() {
        synchronized(guard) { pending = emptyMap(); pendingSize = 0; pendingDigest = "" }
    }
}
