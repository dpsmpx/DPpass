// Корневой проект ничего не собирает: правила модулей — в build-logic,
// версии — в gradle/libs.versions.toml.
//
// Стиль Kotlin — ktlint (D-63): правила — в .editorconfig. ktlint берётся
// одним файлом из своей конфигурации и только этими задачами: сборке APK и
// cli он не нужен. Проверка — шаг project.build (tools/hostcheck/steps.sh).
val ktlint: Configuration by configurations.creating

dependencies {
    ktlint(variantOf(libs.ktlint.cli) { classifier("all") }) { isTransitive = false }
}

// Исходники и скрипты сборки всех модулей и build-logic; вывод сборки — мимо.
val ktlintFiles = listOf("**/src/**/*.kt", "**/*.kts", "!**/build/**")

tasks.register<JavaExec>("ktlintCheck") {
    description = "Стиль Kotlin по .editorconfig (D-63): нарушения — ошибка"
    group = "verification"
    classpath = ktlint
    mainClass.set("com.pinterest.ktlint.Main")
    workingDir = rootDir
    args(listOf("--relative") + ktlintFiles)
}

tasks.register<JavaExec>("ktlintFormat") {
    description = "Исправить стиль Kotlin по .editorconfig (D-63); что не исправилось — список"
    group = "formatting"
    classpath = ktlint
    mainClass.set("com.pinterest.ktlint.Main")
    workingDir = rootDir
    args(listOf("--relative", "--format") + ktlintFiles)
}
