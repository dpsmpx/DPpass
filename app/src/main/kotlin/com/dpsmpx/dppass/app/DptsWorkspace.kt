package com.dpsmpx.dppass.app

import com.dpsmpx.dppass.engine.xray.DptsPlan
import com.dpsmpx.dppass.engine.xray.DptsScript
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.nio.ByteBuffer
import java.nio.charset.CharacterCodingException
import java.nio.charset.CodingErrorAction

/** Portable UTF-8 source files and offline plans; no diagnostic execution. */
internal object DptsWorkspace {
    private const val MAX_BYTES = DptsScript.MAX_SOURCE_LENGTH * 4 + 3

    fun read(input: InputStream): String? {
        val out = ByteArrayOutputStream()
        val buffer = ByteArray(4096)
        while (out.size() <= MAX_BYTES) {
            val n = input.read(buffer, 0, minOf(buffer.size, MAX_BYTES + 1 - out.size()))
            if (n < 0) break
            if (n == 0) return null
            out.write(buffer, 0, n)
        }
        if (out.size() > MAX_BYTES) return null
        val text = try {
            Charsets.UTF_8.newDecoder()
                .onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT)
                .decode(ByteBuffer.wrap(out.toByteArray())).toString().removePrefix("\uFEFF")
        } catch (_: CharacterCodingException) {
            return null
        }
        // Unfinished scripts are editable; import never runs or saves them.
        return text.takeIf { it.length <= DptsScript.MAX_SOURCE_LENGTH && '\u0000' !in it }
    }

    fun preview(plan: DptsPlan): String = buildString {
        appendLine(plan.title)
        appendLine("Host: ${plan.host}")
        appendLine("Learn: ${if (plan.observeLearning) "observe" else "off"}")
        if (plan.suite != null) {
            appendLine("Suite: ${plan.suite}")
            if (plan.budgetMs > 0) appendLine("Probe budget: ${plan.budgetMs} ms")
            return@buildString
        }
        appendLine("Probes: ${plan.probes.size}")
        appendLine("Probe budget: ${plan.budgetMs} ms")
        appendLine()
        plan.probes.forEachIndexed { index, probe ->
            appendLine("${index + 1}. ${probe.phase} / ${probe.protocol} / ${probe.method}" +
                " · IP #${probe.ipIndex + 1} · #${probe.attempt} · ${probe.timeoutMs} ms")
        }
    }
}
