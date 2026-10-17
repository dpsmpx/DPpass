plugins {
    id("dppass.test-suite")
}

dependencies {
    testImplementation(project(":connection"))
    testImplementation(testFixtures(project(":connection")))
    testImplementation(libs.kotlinx.coroutines.core)
}
