plugins {
    id("dppass.test-suite")
}

dependencies {
    testImplementation(project(":connection"))
    testImplementation(testFixtures(project(":connection")))
    testImplementation(libs.kotlinx.coroutines.core)
}

// Тест JNI на хосте (D-25, docs/TESTING.md, «Мост Xray и JNI»): тот же мост
// tools/xray, собранный для JVM хоста (tools/xray/native.py host), в этой JVM.
// Отдельный набор исходников: без библиотеки он не запускается, поэтому в
// `check` не входит; его запускает шаг hostcheck «Xray: мост и JNI».
val xrayJni: SourceSet = sourceSets.create("xrayJni")
configurations[xrayJni.implementationConfigurationName].extendsFrom(configurations.testImplementation.get())
configurations[xrayJni.runtimeOnlyConfigurationName].extendsFrom(configurations.testRuntimeOnly.get())

val xrayLib: Provider<String> = providers.gradleProperty("dppass.xray.lib")
val repoRoot: File = rootDir

tasks.register<Test>("xrayJniTest") {
    description = "Мост Xray через JNI в JVM хоста; нужен -Pdppass.xray.lib=путь к libdppassxray.so"
    group = "verification"
    testClassesDirs = xrayJni.output.classesDirs
    classpath = xrayJni.runtimeClasspath
    val lib = xrayLib.map { repoRoot.resolve(it).absoluteFile }
    inputs.files(lib).withPropertyName("xrayLib").optional()
    systemProperty("dppass.xray.lib", lib.map { it.path }.getOrElse(""))
    doFirst {
        val f = lib.orNull
        if (f == null || !f.isFile) {
            throw GradleException(
                "нет библиотеки ядра для хоста: python3 tools/xray/native.py host, " +
                    "затем -Pdppass.xray.lib=build/xray/host/libdppassxray.so",
            )
        }
    }
}

// Без библиотеки тест не запускается, но компилируется в каждой сборке: ошибка
// в нём видна сразу, а не только на машине с Go.
tasks.named("check") { dependsOn(xrayJni.classesTaskName) }
