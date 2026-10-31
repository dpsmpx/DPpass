import com.dpsmpx.dppass.build.XrayGeodataTask

// Оболочка Linux (D-74): окно Swing и туннель TUN над теми же модулями, что у Android.
plugins {
    id("dppass.kotlin-application")
}

/** Пакет JDK с fd сокетов (D-79): тот же флаг — у пакета и у тестов. */
val addExports = "--add-exports=java.base/sun.nio.ch=ALL-UNNAMED"

// Версия оболочки — своя (D-74): в имени пакета и в `User-Agent` подписки (D-33), из манифеста jar.
version = "0.1.20-dev"

tasks.jar { manifest { attributes("Implementation-Version" to project.version) } }

tasks.test { jvmArgs(addExports) }

dependencies {
    implementation(project(":connection"))
    implementation(libs.kotlinx.coroutines.core)
    testImplementation(libs.kotlinx.coroutines.test)
    // Фиктивное ядро и хранилище в памяти — для автообновления подписок (D-77).
    testImplementation(testFixtures(project(":connection")))
}

application {
    mainClass.set("com.dpsmpx.dppass.desktop.MainKt")
    applicationName = "dppass-desktop"
    // Вывод и имена файлов — UTF-8 при любой локали; сглаживание шрифтов — как в системе.
    // Нативная библиотека ядра грузится `System.load` (D-74): JDK 24+ без разрешения
    // предупреждает об этом при каждом запуске (JEP 472); флаг понимают и JDK 17–23.
    // fd сокета пробы для метки SO_MARK (D-79) — только через sun.nio.ch: другого пути у JVM нет.
    applicationDefaultJvmArgs = listOf(
        "-Dfile.encoding=UTF-8",
        "-Dsun.jnu.encoding=UTF-8",
        "-Dawt.useSystemAAFontSettings=on",
        "--enable-native-access=ALL-UNNAMED",
        addExports,
    )
}

val xray = rootProject.layout.projectDirectory.dir("tools/xray")

// Библиотека ядра для ПК (D-74): tools/xray/native.py desktop — без тестового входа,
// экспорт JNI сверяется с XrayJni и LinuxNative. Без Go сборка падает: пакет без ядра бесполезен.
val xrayNative = tasks.register<Exec>("xrayNativeDesktop") {
    description = "libdppassxray.so для ПК: tools/xray/native.py desktop"
    val out = layout.buildDirectory.dir("xray-native")
    inputs.files(
        xray.asFileTree.matching {
            include("jni/**/*.go", "bridge/**/*.go", "go.mod", "go.sum", "native.py", "goenv.py")
            exclude("**/*_test.go")
        },
        rootProject.layout.projectDirectory.file("engine/src/main/kotlin/com/dpsmpx/dppass/engine/xray/XrayRuntime.kt"),
        layout.projectDirectory.file("src/main/kotlin/com/dpsmpx/dppass/desktop/LinuxNative.kt"),
    ).withPathSensitivity(PathSensitivity.RELATIVE)
    outputs.dir(out)
    commandLine("python3", xray.file("native.py").asFile.path, "desktop", "--out", out.get().asFile.path)
}

// Набор геоданных (D-27) — тот же сборщик, что для APK.
val geodata = tasks.register<XrayGeodataTask>("xrayGeodataDesktop") {
    description = "набор геоданных для ПК: tools/xray/geodata.py"
    sources.from(
        xray.asFileTree.matching {
            include("geodata/**", "go.mod", "go.sum", "geodata.py", "goenv.py")
            exclude("**/*_test.go")
        },
        rootProject.layout.projectDirectory.file("gradle/libs.versions.toml"),
        rootProject.layout.projectDirectory.file("docs/PROVENANCE.md"),
    )
    script.set(xray.file("geodata.py"))
    outputDir.set(layout.buildDirectory.dir("geodata"))
}

// Пакет: bin/, lib/ (jar), native/libdppassxray.so, geodata/, package/ (запуск, polkit, ярлык, значок),
// LICENSE. PKGBUILD с суммой архива пишет tools/desktop/package.py.
distributions.named("main") {
    contents {
        from(xrayNative) { into("native") }
        from(geodata)
        from(layout.projectDirectory.dir("package")) {
            into("package")
            exclude("PKGBUILD.in")
        }
        from(rootProject.layout.projectDirectory.file("LICENSE"))
    }
}
