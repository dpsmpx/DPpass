package com.dpsmpx.dppass.build

import org.gradle.api.GradleException
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/** ABI библиотеки ядра (D-88): по умолчанию все три; для Termux — только названные; опечатка — отказ. */
class NativeAbisTest {
    @Test
    fun emptyMeansAllThree() {
        assertTrue(XrayNativeTask.abiArgs(emptyList()).isEmpty(), "без --abi native.py собирает все три")
        assertEquals(listOf("arm64-v8a", "armeabi-v7a", "x86_64"), XrayNativeTask.ALL)
    }

    @Test
    fun onlyNamedAbis() {
        assertEquals(listOf("--abi", "arm64-v8a"), XrayNativeTask.abiArgs(listOf("arm64-v8a")))
    }

    @Test
    fun unknownOrRepeatedAbiFailsTheBuild() {
        assertFailsWith<GradleException> { XrayNativeTask.abiArgs(listOf("arm64")) }
        assertFailsWith<GradleException> { XrayNativeTask.abiArgs(listOf("arm64-v8a", "arm64-v8a")) }
    }
}
