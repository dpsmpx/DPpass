// Модули DPpass. Граница между ними — граница ответственности
// (docs/ARCHITECTURE.md, §2): зависимости между модулями проверяет
// компилятор, а допустимые направления — tools/hostcheck/check_modules.py.
pluginManagement {
    includeBuild("build-logic")
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
    }
}

dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        google()
        mavenCentral()
    }
}

rootProject.name = "DPpass"

// Ядро: чистый Kotlin/JVM, собирается и проверяется без Android SDK.
include(
    ":diagnostics",
    ":core",
    ":routing",
    ":config",
    ":engine",
    ":network",
    ":storage",
    ":subscriptions",
    ":tunnel",
    ":connection",
    ":cli",
    // Оболочка Linux (D-74): окно Swing и туннель TUN.
    ":desktop",
)

// Межмодульные тесты.
include(":tests:integration", ":tests:regression", ":tests:fuzz")

// Android-приложение — только если есть Android SDK. Без SDK сборка
// ядра работает, а hostcheck в полном режиме называет пропуск ошибкой
// (docs/PROCESS.md, «Проверки»), а не молча его пропускает.
fun androidSdkPresent(): Boolean {
    val env = System.getenv("ANDROID_HOME") ?: System.getenv("ANDROID_SDK_ROOT")
    if (env != null && file(env).isDirectory) return true
    val local = file("local.properties")
    if (!local.isFile) return false
    val dir = local.readLines().firstOrNull { it.startsWith("sdk.dir=") }?.substringAfter("=")
    return dir != null && file(dir).isDirectory
}

if (androidSdkPresent()) {
    include(":app")
} else {
    logger.lifecycle("DPpass: Android SDK не найден — модуль :app не подключён")
}
