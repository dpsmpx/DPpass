// Активация с last-known-good и адаптивная политика подключения.
plugins {
    id("dppass.kotlin-library")
    // Здоровье по модели сети (SimulatedHealthChecker) — для тестов и cli, не для APK.
    `java-test-fixtures`
}

dependencies {
    api(project(":engine"))
    api(project(":network"))
    api(project(":storage"))
    api(project(":subscriptions"))
    api(project(":tunnel"))
    implementation(libs.kotlinx.coroutines.core)
    testFixturesApi(testFixtures(project(":engine")))
    testFixturesApi(testFixtures(project(":network")))
    testImplementation(libs.kotlinx.coroutines.test)
}
