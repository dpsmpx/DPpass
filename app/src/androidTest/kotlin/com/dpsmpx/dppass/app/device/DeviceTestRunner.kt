package com.dpsmpx.dppass.app.device

import android.app.Activity
import android.app.Instrumentation
import android.os.Bundle

/**
 * Запускатель тестов на телефоне (D-75): платформенный `Instrumentation`,
 * без AndroidX Test и JUnit (D-34, D-18). Запуск — оболочкой `adb`:
 *
 *     adb shell am instrument -w com.dpsmpx.dppass.test/com.dpsmpx.dppass.app.device.DeviceTestRunner
 *
 * `-e tests Набор.тест,…` — только тесты, в чьём полном имени есть одна из
 * подстрок. Итог — список «✓/✗» с причиной отказа; с `-r` — ещё строки
 * статуса в обычном формате инструментирования (начало, исход, стек).
 */
class DeviceTestRunner : Instrumentation() {
    private var filter: List<String> = emptyList()

    override fun onCreate(arguments: Bundle?) {
        super.onCreate(arguments)
        filter = arguments?.getString(ARG_TESTS)?.split(',')?.map(String::trim)?.filter(String::isNotEmpty).orEmpty()
        start()
    }

    override fun onStart() {
        super.onStart()
        val cases = DeviceTests.ALL.flatMap { s -> s.cases.map { s.name to it } }
            .filter { (suite, case) -> filter.isEmpty() || filter.any { "$suite.${case.name}".contains(it) } }
        val device = Device(this)
        val lines = mutableListOf<String>()
        var failed = 0
        cases.forEachIndexed { i, (suite, case) ->
            val status = Bundle().apply {
                putString(KEY_ID, ID)
                putString(KEY_CLASS, suite)
                putString(KEY_TEST, case.name)
                putInt(KEY_NUM_TESTS, cases.size)
                putInt(KEY_CURRENT, i + 1)
            }
            sendStatus(STATUS_START, Bundle(status))
            val error = try {
                case.run(device)
                null
            } catch (e: Throwable) {
                e
            } finally {
                device.close()
            }
            if (error == null) {
                lines += "✓ $suite.${case.name}"
                sendStatus(STATUS_OK, status)
            } else {
                failed++
                lines += "✗ $suite.${case.name}: ${error.message ?: error.javaClass.simpleName}"
                // Стек — только кадры: в тестах нет секретов, а место отказа нужно (D-22 — о журнале приложения).
                val frames = error.stackTrace.take(STACK_FRAMES).joinToString("\n") { "    at $it" }
                status.putString(KEY_STACK, "${error.javaClass.name}: ${error.message}\n$frames")
                sendStatus(if (error is AssertionError) STATUS_FAILURE else STATUS_ERROR, status)
            }
        }
        lines += if (cases.isEmpty()) {
            "Ни одного теста: фильтр «${filter.joinToString(",")}» ничего не выбрал."
        } else if (failed == 0) {
            "Все ${cases.size} тестов прошли."
        } else {
            "Не прошли $failed из ${cases.size}."
        }
        finish(Activity.RESULT_OK, Bundle().apply { putString(KEY_STREAM, lines.joinToString("\n", postfix = "\n")) })
    }

    private companion object {
        const val ARG_TESTS = "tests"
        const val ID = "DPpassDeviceTests"

        // Ключи и коды — как у обычных запускателей: их понимает `am instrument -r`.
        const val KEY_ID = "id"
        const val KEY_CLASS = "class"
        const val KEY_TEST = "test"
        const val KEY_NUM_TESTS = "numtests"
        const val KEY_CURRENT = "current"
        const val KEY_STACK = "stack"
        const val KEY_STREAM = "stream"
        const val STATUS_START = 1
        const val STATUS_OK = 0
        const val STATUS_ERROR = -1
        const val STATUS_FAILURE = -2
        const val STACK_FRAMES = 12
    }
}
