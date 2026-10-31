package com.dpsmpx.dppass.desktop

/**
 * Уведомление рабочего стола (D-92): показано ли — false, если системе
 * его не передать; тогда остаётся полоса в окне. Текст — без адресов и
 * имён серверов (D-57): его видит оболочка рабочего стола.
 */
fun interface DesktopNotifier {
    fun show(title: String, text: String): Boolean
}

/** Linux (D-74): `notify-send` из libnotify, если он есть. */
class DesktopNotify(
    private val run: (List<String>) -> CommandResult = { SystemCommand.run(BINARIES, "notify-send (libnotify)", it, TIMEOUT_SECONDS) },
) : DesktopNotifier {
    /** Показано ли: false — нет `notify-send` или он отказал. */
    override fun show(title: String, text: String): Boolean = run(listOf("--app-name=DPpass", title, text)).code == 0

    companion object {
        /** Не из PATH (T17): `notify-send` — из пакета libnotify. */
        val BINARIES: List<String> = listOf("/usr/bin/notify-send", "/bin/notify-send")
        const val TIMEOUT_SECONDS: Long = 5
    }
}
