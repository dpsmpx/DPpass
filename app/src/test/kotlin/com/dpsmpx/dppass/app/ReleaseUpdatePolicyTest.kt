package com.dpsmpx.dppass.app

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull

class ReleaseUpdatePolicyTest {
    private val hash = "a".repeat(64)
    private val tag = "v0.8.3-rc.8"
    private val name = "DPpass-update-164-$hash-arm64-v8a.apk"
    private val url = "https://github.com/dpsmpx/DPpass/releases/download/$tag/$name"

    @Test fun acceptsOnlyNewerCompatibleAsset() {
        val update = ReleaseUpdatePolicy.candidate(tag, name, 42, url, 163)
        assertEquals(164L, update?.code)
        assertEquals(hash, update?.sha256)
        assertNull(ReleaseUpdatePolicy.candidate(tag, name, 42, url, 164))
        assertNull(ReleaseUpdatePolicy.candidate(tag, name, 42, url, 165))
        assertNull(ReleaseUpdatePolicy.candidate(tag, name, 0, url, 163))
        assertNull(ReleaseUpdatePolicy.candidate(tag, name, ReleaseUpdatePolicy.MAX_APK_BYTES + 1, url, 163))
        assertNull(ReleaseUpdatePolicy.candidate(tag, name, 42, url.replace("github.com", "example.com"), 163))
        assertNull(ReleaseUpdatePolicy.candidate(tag, name.replace("arm64-v8a", "x86"), 42, url, 163))
        assertNull(ReleaseUpdatePolicy.candidate("bad", name, 42, url, 163))
    }

    @Test fun highestCodeWinsAndAmbiguousCandidatesFailClosed() {
        val old = ReleaseUpdatePolicy.candidate(tag, name, 42, url, 163)!!
        val newer = old.copy(code = 165)
        assertEquals(newer, ReleaseUpdatePolicy.best(listOf(newer, old)))
        assertEquals(old, ReleaseUpdatePolicy.best(listOf(old, old)))
        assertNull(ReleaseUpdatePolicy.best(listOf(old, old.copy(sha256 = "b".repeat(64)))))
        assertNull(ReleaseUpdatePolicy.best(emptyList()))
    }
}
