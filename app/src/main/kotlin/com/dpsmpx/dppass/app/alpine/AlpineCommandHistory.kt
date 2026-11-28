package com.dpsmpx.dppass.app.alpine

/** Session-only history: does not persist commands or passwords to storage. */
internal class AlpineCommandHistory(private val capacity: Int = 100) {
    private val commands = ArrayList<String>()
    private var cursor = 0
    private var draft = ""

    init { require(capacity > 0) }

    fun record(command: String) {
        if (command.isNotBlank() && command.length <= 4096 && commands.lastOrNull() != command) {
            commands.add(command)
            if (commands.size > capacity) commands.removeAt(0)
        }
        cursor = commands.size
        draft = ""
    }

    fun previous(current: String): String? {
        if (commands.isEmpty()) return null
        if (cursor == commands.size) draft = current
        cursor = (cursor - 1).coerceAtLeast(0)
        return commands[cursor]
    }

    fun next(): String? {
        if (cursor == commands.size) return null
        cursor++
        return if (cursor == commands.size) draft else commands[cursor]
    }

    fun recent(): List<String> = commands.asReversed().toList()

    fun clear() {
        commands.clear()
        cursor = 0
        draft = ""
    }
}
