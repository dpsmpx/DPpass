package com.dpsmpx.dppass.app

import android.content.Context
import com.dpsmpx.dppass.config.TransportClass
import com.dpsmpx.dppass.config.transportClass
import com.dpsmpx.dppass.connection.ConnectionPlan
import com.dpsmpx.dppass.connection.ConnectionReport
import com.dpsmpx.dppass.connection.DPpassCore
import com.dpsmpx.dppass.connection.HealthState
import com.dpsmpx.dppass.connection.ServerLearningEvidence
import com.dpsmpx.dppass.connection.ServerAutoOrdering
import com.dpsmpx.dppass.connection.ServerAutoScore
import com.dpsmpx.dppass.network.NetworkType
import com.dpsmpx.dppass.diagnostics.Safe
import org.json.JSONArray
import org.json.JSONObject
import java.security.MessageDigest
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

    // A connection attempt needs its *pre-outcome* features to avoid
    // leaking the answer into the training sample. Kept only in RAM.
    private data class Pending(val features: DoubleArray, val scenario: Int, val sparseFeatures: Map<Long, Double>)
    private class Training(
        val features: Map<String, Pending>, val hidden: Int, val digest: String, val observations: List<Long>,
    )
    private class Batch(val original: ConnectionPlan, val network: NetworkType, val training: Training?)
    private val learning = ServerLearningWindow<ConnectionPlan, Batch>()

    internal fun beginLearning(): Any = learning.begin()
    internal fun finishLearning(token: Any) = learning.finish(token)

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
        val used = Zapret2NeuralModel.denseCount(
            Zapret2NeuralModel.Kind.SERVER,
            model.getJSONArray("hidden").length(), model.getJSONArray("deep_hidden").length(),
        )
        return model.getLong("parameters") - used
    }

    /** Stable keyed index; the JSON contains only numeric weights, never IDs. */
    private fun sparseIndex(seed: String, scenario: Int, profileId: String,
                            feature: Int, bucket: Int, capacity: Long): Long? {
        val data = "${seed}|${scenario}|${profileId}|${feature}|${bucket}"
        val hash = MessageDigest.getInstance("SHA-256").digest(data.encodeToByteArray())
        var n = 0L
        for (i in 0 until 7) n = (n shl 8) or (hash[i].toLong() and 255L)
        return ServerContextHead.sparseIndex(scenario, capacity, n)
    }

    private fun sparseFeatures(seed: String, x: DoubleArray, scenario: Int, profileId: String,
                               capacity: Long): Map<Long, Double> {
        if (ServerContextHead.sparseSlots(scenario, capacity) == 0L) return emptyMap()
        return buildMap {
            for (i in x.indices) {
                if (x[i] <= 0.0) continue
                val bucket = (x[i] * 15.0).toInt().coerceIn(0, 15)
                val index = checkNotNull(sparseIndex(seed, scenario, profileId, i, bucket, capacity))
                put(index, (get(index) ?: 0.0) + x[i])
            }
        }
    }

    private fun forward(model: JSONObject, x: DoubleArray, scenario: Int,
                        sparseLogit: Double): Pair<Double, DoubleArray> {
        val hidden = lastHidden(model, x)
        val out = model.getJSONArray("output").getJSONArray(scenario)
        val weights = DoubleArray(hidden.size) { out.getDouble(it) }
        val bias = model.getJSONArray("output_bias").getDouble(scenario)
        val probability = ServerContextHead.probability(weights, bias, hidden, sparseLogit)
        return probability to hidden
    }

    /**
     * Never changes the candidate SET. Restrict to healthy/unknown pairs
     * and adjacent swaps; backoff failures retain planner placement.
     */
    internal fun rerank(context: Context, plan: ConnectionPlan, core: DPpassCore,
               network: NetworkType, now: Long, token: Any): ConnectionPlan {
        val snapshot = Zapret2NeuralModel.readVerified(context, Zapret2NeuralModel.Kind.SERVER)
        if (snapshot == null || plan.attempts.isEmpty()) {
            // No server identities, IP addresses or subscription URLs in logs.
            core.log.info("server_auto_model", "installed" to (snapshot != null),
                "candidates" to plan.attempts.size, "reordered" to 0)
            if (plan.attempts.isEmpty()) finishLearning(token)
            else learning.publish(token, plan, Batch(plan, network, null))
            return plan
        }
        return runCatching {
            val model = JSONObject(snapshot.decodeToString())
            val observations = model.optInt("observations", 0)
            val sparse = model.getJSONObject("sparse")
            val capacity = sparseCapacity(model)
            val seed = model.getString("seed")
            val counts = model.getJSONArray("context_observations")
            val contextObservations = List(counts.length()) { counts.getLong(it) }
            val scored = plan.attempts.mapIndexed { i, attempt ->
                val feat = features(core, attempt.profile, i, network, now)
                val scenario = ServerAutoContext.of(network, attempt.profile.transportClass).ordinal
                val terms = sparseFeatures(seed, feat, scenario, attempt.profile.id.value, capacity)
                val sparseLogit = terms.entries.sumOf { (index, feature) ->
                    sparse.optDouble(index.toString(), 0.0) * feature
                }
                Triple(attempt, Pending(feat, scenario, terms),
                    forward(model, feat, scenario, sparseLogit).first)
            }
            // Capture features before any outcomes, even for a single server.
            val training = Training(scored.associate { it.first.profile.id.value to it.second },
                model.getJSONArray("hidden").length(), digest(snapshot), contextObservations)
            val ordered = ServerAutoOrdering.rank(plan, scored.map { entry ->
                ServerAutoScore(entry.third, contextObservations[entry.second.scenario])
            }, core.health::of, core.health.lastGood())
            val reordered = ordered.attempts.indices.count { i ->
                ordered.attempts[i].profile.id != plan.attempts[i].profile.id
            }
            core.log.info("server_auto_model", "installed" to true,
                "hidden" to model.getJSONArray("hidden").length(),
                "observations" to observations,
                "candidates" to plan.attempts.size,
                "reordered" to reordered)
            if (learning.publish(token, ordered, Batch(plan, network, training))) ordered else plan
        }.getOrElse {
            finishLearning(token)
            plan
        }
    }

    /** Train only on real orchestrator attempts after content health checks. */
    internal fun observe(context: Context, report: ConnectionReport, core: DPpassCore, token: Any) {
        val batch = learning.take(token, report.plan)
        if (batch == null) {
            core.log.info("server_auto_learning", "trained" to 0, "persisted" to false)
            return
        }
        val training = batch.training
        runCatching {
            for (outcome in serverAutoOutcomes(batch.original, report.plan, report.attempts, batch.network)) {
                outcome.log(core.log, training?.observations?.get(outcome.context.ordinal))
            }
        }.onFailure {
            core.log.warning("server_auto_outcome_failed")
        }
        if (training == null) {
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
        if (digest(raw) != training.digest) {
            core.log.info("server_auto_learning", "trained" to 0,
                "persisted" to false, "replaced" to true)
            return
        }
        runCatching {
            val model = JSONObject(raw.decodeToString())
            if (model.getJSONArray("hidden").length() != training.hidden) {
                core.log.warning("server_auto_learning_failed", "reason" to Safe("model_width_changed"))
                return@runCatching
            }
            val outputRows = model.getJSONArray("output")
            val outBias = model.getJSONArray("output_bias")
            val counts = model.getJSONArray("context_observations")
            val capacity = sparseCapacity(model)
            val sparse = lazy {
                val weights = model.getJSONObject("sparse")
                val recency = model.optJSONArray("sparse_recency")?.let { order ->
                    List(order.length()) { order.getLong(it) }
                }
                ServerSparseWeights(capacity, weights.keys().asSequence().associate { key ->
                    key.toLong() to weights.getDouble(key)
                }, recency)
            }
            var learned = 0
            val seen = mutableSetOf<String>()
            for (attempt in report.attempts) {
                val profileId = attempt.profileId.value
                val pendingAttempt = training.features[profileId] ?: continue
                val x = pendingAttempt.features
                val scenario = pendingAttempt.scenario
                // Only explicitly measured health outcomes are admitted.
                // Engine startup/configuration errors and unchecked success
                // must never become server-model labels.
                val label = when (attempt.measuredServerEvidence()) {
                    ServerLearningEvidence.VERIFIED_SUCCESS -> 1.0
                    ServerLearningEvidence.MEASURED_FAILURE -> 0.0
                    ServerLearningEvidence.NONE -> continue
                }
                if (!seen.add(profileId)) continue
                val terms = pendingAttempt.sparseFeatures
                val sparseLogit = terms.entries.sumOf { (index, feature) -> sparse.value.weight(index) * feature }
                val (p, h) = forward(model, x, scenario, sparseLogit)
                val delta = ServerContextHead.delta(label, p)
                learned++
                // The common feature extractor is frozen. Only this context's
                // output weights and bias are updated; no other head changes.
                val output = outputRows.getJSONArray(scenario)
                for (i in h.indices) {
                    output.put(i, ServerContextHead.update(output.getDouble(i), delta, h[i]))
                }
                outBias.put(scenario, ServerContextHead.update(outBias.getDouble(scenario), delta, 1.0))
                counts.put(scenario, ModelNumericFields.addObservations(counts.getLong(scenario), 1))
                if (terms.isNotEmpty()) sparse.value.learn(terms, delta)
            }
            if (learned == 0) {
                core.log.info("server_auto_learning", "trained" to 0, "persisted" to false)
                return@runCatching
            }
            if (sparse.isInitialized()) {
                val weights = JSONObject()
                val recency = JSONArray()
                for ((index, weight) in sparse.value.entries()) {
                    weights.put(index.toString(), weight)
                    recency.put(index)
                }
                model.put("sparse", weights).put("sparse_recency", recency)
            }
            model.put("observations", ModelNumericFields.addObservations(model.optLong("observations", 0), learned))
            // Revalidate and atomically persist only the numeric model,
            // not the server IDs or training examples.
            val updated = model.toString().encodeToByteArray()
            val persisted = learning.commitIfCurrent(token) {
                Zapret2NeuralModel.storeIfUnchanged(
                    context, Zapret2NeuralModel.Kind.SERVER, raw, updated,
                )
            }
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
        learning.reset()
    }
}
