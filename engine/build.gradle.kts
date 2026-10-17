// Граница ядра: ProxyEngine, BackendCompiler, матрица возможностей.
// Фиктивный бэкенд для доказательства абстракции — тестовая фикстура
// (src/testFixtures): второй бэкенд тестов и cli, в APK его нет (D-25).
plugins {
    id("dppass.kotlin-library")
    `java-test-fixtures`
}

dependencies {
    api(project(":config"))
}

dependencies {
    testImplementation(libs.kotlinx.coroutines.core)
}
