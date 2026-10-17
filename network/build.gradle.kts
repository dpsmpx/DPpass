// Определение состояния сети: пробы, бюджет проб, классификация. От ядра
// не зависит. Модель сетевых условий для тестов и cli — тестовая фикстура
// (src/testFixtures): в APK её нет.
plugins {
    id("dppass.kotlin-library")
    `java-test-fixtures`
}

dependencies {
    api(project(":core"))
}

dependencies {
    testImplementation(libs.kotlinx.coroutines.core)
}
