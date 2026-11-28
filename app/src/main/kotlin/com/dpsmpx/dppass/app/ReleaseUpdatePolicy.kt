package com.dpsmpx.dppass.app

internal data class ReleaseUpdate(val tag: String, val code: Long, val sha256: String, val size: Long, val url: String)

internal object ReleaseUpdatePolicy {
    const val MAX_APK_BYTES = 512L * 1024 * 1024
    private val tagPattern = Regex("v[0-9]+\\.[0-9]+\\.[0-9]+(?:-(?:rc|alpha)\\.[0-9]+)?")
    private val assetPattern = Regex("DPpass-update-([1-9][0-9]{0,9})-([0-9a-f]{64})-arm64-v8a\\.apk")
    fun candidate(tag: String, name: String, size: Long, url: String, installed: Long): ReleaseUpdate? {
        if (!tagPattern.matches(tag) || size !in 1..MAX_APK_BYTES) return null
        val match = assetPattern.matchEntire(name) ?: return null
        val code = match.groupValues[1].toLongOrNull() ?: return null
        if (code <= installed || code > Int.MAX_VALUE) return null
        if (url != "https://github.com/dpsmpx/DPpass/releases/download/$tag/$name") return null
        return ReleaseUpdate(tag, code, match.groupValues[2], size, url)
    }
    fun best(candidates: List<ReleaseUpdate>): ReleaseUpdate? {
        val highest = candidates.maxOfOrNull { it.code } ?: return null
        return candidates.filter { it.code == highest }.distinct().singleOrNull()
    }
}
