package com.dpsmpx.dppass.tunnel

import com.dpsmpx.dppass.config.ConfigLoader
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class TunnelOwnerTest {
    @Test
    fun reconnectRetainsOldTunnelUntilReplacementAndStopClosesOnlyOnce() {
        val ir = ConfigLoader().load(File(System.getProperty("dppass.repoRoot"), "tests/data/configs/valid-multi.json").readText()).valueOrNull()!!.ir
        val spec = TunnelSpecBuilder.build(ir, "com.dpsmpx.dppass", PlatformTraits(true)).valueOrNull()!!
        var open = 0
        fun establish(): TunnelHandle {
            open++
            return object : TunnelHandle {
                override val fd = open
                override val spec = spec
                override fun protect(socketFd: Int) = true
                override fun close() { open-- }
            }
        }
        val owner = TunnelOwner()
        val first = establish()
        owner.replace(first)
        assertTrue(owner.present)
        assertEquals(1, open, "отказ до нового establish не закрывает старый fd")
        val replacement = establish()
        assertEquals(2, open, "новый fd уже открыт до закрытия старого")
        owner.replace(replacement)
        assertEquals(1, open)
        owner.replace(replacement)
        assertEquals(1, open, "повторная передача владения не закрывает текущий fd")
        owner.close()
        owner.close()
        assertEquals(0, open)
    }
}
