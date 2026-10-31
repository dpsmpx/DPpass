package com.dpsmpx.dppass.app.screens

import androidx.test.platform.app.InstrumentationRegistry
import com.dpsmpx.dppass.app.device.Device
import com.dpsmpx.dppass.app.device.DeviceTests
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.ParameterizedRobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.annotation.Config

/**
 * Тесты экранов телефона (D-75) на JVM под Robolectric (D-86): те же наборы
 * `DeviceTests.ALL`, те же руки и глаза ([Device]), каждый тест — отдельным
 * случаем JUnit, по-русски и по-английски: русские подписи длиннее, и
 * размеры у них свои. Android — образ SDK 36 (Android 16), как `targetSdk`.
 */
@RunWith(ParameterizedRobolectricTestRunner::class)
@Config(sdk = [26, 29, 36])
class ScreenTest(private val name: String, private val language: String) {
    @Test
    fun run() {
        RuntimeEnvironment.setQualifiers(language)
        val case = DeviceTests.ALL.flatMap { s -> s.cases.map { "${s.name}.${it.name}" to it } }.single { it.first == name }.second
        val d = Device(InstrumentationRegistry.getInstrumentation(), JvmHands())
        try {
            case.run(d)
        } finally {
            d.close()
        }
    }

    companion object {
        private val LANGUAGES = listOf("ru", "en")

        @JvmStatic
        @ParameterizedRobolectricTestRunner.Parameters(name = "{0} [{1}]")
        fun cases(): List<Array<Any>> = DeviceTests.ALL.flatMap { s -> s.cases.flatMap { c -> LANGUAGES.map { arrayOf<Any>("${s.name}.${c.name}", it) } } }
    }
}
