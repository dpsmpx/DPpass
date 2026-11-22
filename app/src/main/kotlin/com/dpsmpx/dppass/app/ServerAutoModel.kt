package com.dpsmpx.dppass.app

import android.content.Context
import com.dpsmpx.dppass.config.TransportClass
import com.dpsmpx.dppass.config.transportClass
import com.dpsmpx.dppass.connection.ConnectionPlan
import com.dpsmpx.dppass.connection.ConnectionReport
import com.dpsmpx.dppass.connection.DPpassCore
import com.dpsmpx.dppass.connection.HealthState
import com.dpsmpx.dppass.network.NetworkType
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
    private var pending: Map<String, DoubleArray> = emptyMap()
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

    private fun forward(model: JSONObject, x: DoubleArray): Pair<Double, DoubleArray> {
        val matrix = model.getJSONArray("hidden")
        val bias = model.getJSONArray("bias")
        val out = model.getJSONArray("output").getJSONArray(0)
        val hidden = DoubleArray(matrix.length()) { i ->
            val row = matrix.getJSONArray(i)
            var sum = bias.getDouble(i)
            for (j in 0 until INPUTS) sum += row.getDouble(j) * x[j]
            max(0.0, sum)
        }
        var z = model.getJSONArray("output_bias").getDouble(0)
        for (i in hidden.indices) z += out.getDouble(i) * hidden[i]
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
            resetTransient()
            return plan
        }
        return runCatching {
            val model = JSONObject(snapshot.decodeToString())
            val scored = plan.attempts.mapIndexed { i, attempt ->
                val feat = features(core, attempt.profile, i, network, now)
                Triple(attempt, feat, forward(model, feat).first)
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
                if (leftHealth != rightHealth || leftHealth == HealthState.FAILED) continue
                val advantage = right.third - left.third
                if (advantage > 0.12) {
                    scored[i] = right
                    scored[i + 1] = left
                }
            }
            plan.copy(attempts = scored.map { it.first })
        }.getOrElse {
            resetTransient()
            plan
        }
    }

    private fun clamped(v: Double) = v.coerceIn(-4.0, 4.0)

    /** Train only on real orchestrator attempts after content health checks. */
    fun observe(context: Context, report: ConnectionReport) {
        val (feats, expectedHidden, originalDigest) = synchronized(guard) {
            val copy = pending
            val size = pendingSize
            val previous = pendingDigest
            pending = emptyMap()
            pendingSize = 0
            pendingDigest = ""
            Triple(copy, size, previous)
        }
        if (feats.isEmpty()) return
        val raw = Zapret2NeuralModel.readVerified(context, Zapret2NeuralModel.Kind.SERVER) ?: return
        // A user may regenerate another model of the same width while
        // connecting. Never train stale features into replacement weights.
        if (digest(raw) != originalDigest) return
        runCatching {
            val model = JSONObject(raw.decodeToString())
            if (model.getJSONArray("hidden").length() != expectedHidden) return@runCatching
            val hiddenRows = model.getJSONArray("hidden")
            val bias = model.getJSONArray("bias")
            val outputRows = model.getJSONArray("output")
            val output = outputRows.getJSONArray(0)
            val outBias = model.getJSONArray("output_bias")
            for (attempt in report.attempts) {
                val x = feats[attempt.profileId.value] ?: continue
                // Core-local/backend failures are not server failures.
                val failure = attempt.failure?.code?.name
                if (failure in setOf("BACKEND_ALREADY_RUNNING", "LOCAL_PROXY_UNAVAILABLE", "TUN_ESTABLISH_FAILED"))
                    continue
                val (p, h) = forward(model, x)
                val delta = LR * ((if (attempt.ok) 1.0 else 0.0) - p)
                val oldWeights = DoubleArray(h.size) { output.getDouble(it) }
                for (i in h.indices) {
                    output.put(i, clamped(oldWeights[i] + delta * h[i]))
                }
                outBias.put(0, clamped(outBias.getDouble(0) + delta))
                for (i in h.indices) {
                    if (h[i] <= 0.0) continue
                    val scale = delta * oldWeights[i] * 0.1
                    val row = hiddenRows.getJSONArray(i)
                    bias.put(i, clamped(bias.getDouble(i) + scale))
                    for (j in 0 until INPUTS) row.put(j, clamped(row.getDouble(j) + scale * x[j]))
                }
            }
            // Revalidate and atomically persist only the numeric model,
            // not the server IDs or training examples.
            Zapret2NeuralModel.store(context, Zapret2NeuralModel.Kind.SERVER, model.toString().encodeToByteArray())
        }
    }

    /** A network handoff changes the meaning of latency and failure data. */
    fun resetTransient() {
        synchronized(guard) { pending = emptyMap(); pendingSize = 0; pendingDigest = "" }
    }
}
