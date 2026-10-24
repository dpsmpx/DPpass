package com.dpsmpx.dppass.app.device

/** Тест на телефоне (D-75): имя и что делать. Провал — исключение с причиной для человека. */
class DeviceCase(val name: String, val run: (Device) -> Unit)

/** Набор тестов одной темы. */
interface DeviceSuite {
    val name: String
    val cases: List<DeviceCase>
}

/**
 * Все наборы — явным списком, без поиска классов по dex: что запускается,
 * видно здесь. Набор, которого нет в списке, — ошибка `check_device_tests.py`.
 */
object DeviceTests {
    val ALL: List<DeviceSuite> = listOf(LaunchTests, AccessibilityTests, NavigationTests)
}

/** Условие теста; не выполнено — провал с [message]. */
fun expect(condition: Boolean, message: () -> String) {
    if (!condition) throw AssertionError(message())
}
