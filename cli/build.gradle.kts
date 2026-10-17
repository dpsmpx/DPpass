// Оболочка приложения на JVM: те же модули, что у Android, без UI.
plugins {
    id("dppass.kotlin-application")
}

dependencies {
    implementation(project(":connection"))
    // Модель сети и фиктивное ядро — фикстуры тестов: cli ими демонстрирует план и замеры.
    implementation(testFixtures(project(":connection")))
    implementation(libs.kotlinx.coroutines.core)
}

application {
    mainClass.set("com.dpsmpx.dppass.cli.MainKt")
    applicationName = "dppass-cli"
}

// Вывод — UTF-8 независимо от локали системы (сообщения диагностики — по-русски).
tasks.named<JavaExec>("run") { jvmArgs("-Dstdout.encoding=UTF-8", "-Dstderr.encoding=UTF-8") }
application.applicationDefaultJvmArgs = listOf("-Dstdout.encoding=UTF-8", "-Dstderr.encoding=UTF-8", "-Dfile.encoding=UTF-8")
