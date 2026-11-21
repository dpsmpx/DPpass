package com.dpsmpx.dppass.app.alpine

/** Immutable argv construction: package names never become shell commands. */
internal object AlpinePackageCommand {
    private val packagePattern = Regex("[A-Za-z0-9][A-Za-z0-9._+@-]{0,79}")

    fun arguments(action: String, names: String): List<String> {
        require(action in setOf("add", "update", "upgrade")) { "Недопустимая команда apk" }
        val packages = names.trim().split(Regex("\\s+")).filter { it.isNotEmpty() }
        if (action == "add") {
            require(packages.isNotEmpty() && packages.size <= 20 && packages.all { packagePattern.matches(it) }) {
                "Укажите 1–20 корректных имён пакетов"
            }
        } else {
            require(packages.isEmpty()) { "Для обновления имена пакетов не нужны" }
        }
        return listOf("/sbin/apk", action, "-U", "--no-progress") + packages
    }
}
