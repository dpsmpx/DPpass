// Android-приложение DPpass: оболочка над DPpassCore (D-02, D-17).
// Подключается, только если найден Android SDK (settings.gradle.kts).
import com.dpsmpx.dppass.build.AppIdentity
import com.dpsmpx.dppass.build.LegalNoticesTask
import com.dpsmpx.dppass.build.XrayGeodataTask
import com.dpsmpx.dppass.build.XrayNativeTask
import java.net.URI
import java.security.MessageDigest
import java.nio.ByteBuffer
import java.nio.ByteOrder

plugins {
    id("dppass.android-app")
}

/** Alpine/PRoot from DPmetaApp is intentionally opt-in while device validation is pending.
 * Use -Pdppass.alpine=true to build the ARM64 Linux console; regular APKs stay unchanged.
 */
val alpineEnabled = providers.gradleProperty("dppass.alpine").map(String::toBoolean).getOrElse(false)


// Личность устанавливаемого приложения (D-47). Пространство имён кода —
// всегда `com.dpsmpx.dppass` (ниже `namespace`): меняется только личность.
//   * отладочная сборка и проверки — стабильная личность (детерминизм);
//   * сборка release — тоже стабильная личность `com.dpsmpx.dppass` (D-114):
//     пакет не зависит ни от ключа, ни от пароля, ни от сборки.
// Случайная личность D-47/D-49 остаётся только явным выбором:
// `-Pdppass.randomIdentity=true` (зерно — `dppass.identitySeed`).
val randomIdentity = providers.gradleProperty("dppass.randomIdentity").map(String::toBoolean).getOrElse(false)
val identitySeed = AppIdentity.seedOf(providers.gradleProperty("dppass.identitySeed").orNull)
val releaseIdentity = if (randomIdentity) AppIdentity.random(identitySeed) else AppIdentity.STABLE

// Тесты экранов на JVM (D-86): Robolectric — только по свойству dppass.robolectric
// (шаг проверки «Android: экраны на JVM»). Обычная сборка, в том числе в Termux,
// его не тянет: «Android целиком» — 213 МБ.
val robolectric = providers.gradleProperty("dppass.robolectric").isPresent

// API, на котором идут экраны и пути (D-108): 36 по умолчанию, 26 и 29 — младшие
// ветки кода (D-104). Один прогон — одно API: ядро Xray грузится в JVM один раз,
// а у каждого API Robolectric — свой загрузчик классов.
val robolectricSdk: Int = providers.gradleProperty("dppass.robolectric.sdk").map(String::toInt).getOrElse(36)

// Ядро Xray в тестах путей на JVM (D-90): библиотека моста для хоста — та же, что у XrayJniTest.
val repoRoot: File = rootDir
val xrayHostLib: Provider<File> = providers.gradleProperty("dppass.xray.lib").map { repoRoot.resolve(it).absoluteFile }

/**
 * Образы «Android целиком» для Robolectric — через Gradle, с проверкой суммы (аудит A-7), а не
 * загрузкой из теста; по образу на API (D-108): один модуль трёх версий в одной конфигурации
 * Gradle свёл бы к старшей.
 */
val robolectricImages: Map<Int, Configuration> = listOf(26, 29, 36).associateWith { sdk ->
    configurations.create("robolectricAndroid$sdk") {
        isCanBeConsumed = false
        isTransitive = false
    }
}
require(robolectricSdk in robolectricImages) { "dppass.robolectric.sdk — одно из ${robolectricImages.keys}, а не $robolectricSdk" }

android {
    namespace = "com.dpsmpx.dppass"
    compileSdk = libs.versions.android.compileSdk.get().toInt()
    if (alpineEnabled) {
        // Native PTY from DPmetaApp/dpai, part of the opt-in Alpine console.
        ndkVersion = libs.versions.android.ndk.get()
        externalNativeBuild {
            cmake {
                path = file("src/main/cpp/CMakeLists.txt")
                version = "3.22.1"
            }
        }
    }


    defaultConfig {
        // Личность по умолчанию — стабильная (отладка, проверки); release её
        // переопределяет (D-47). Публичный applicationId — com.dpsmpx.dppass
        // (D-103) — рандомизация туда не идёт.
        applicationId = AppIdentity.STABLE.applicationId
        minSdk = libs.versions.android.minSdk.get().toInt()
        targetSdk = libs.versions.android.targetSdk.get().toInt()
        versionCode = 157
        versionName = "0.8.3-rc.1"
        // Ярлык приложения — через placeholder: стабильный для отладки,
        // случайный для личного release (D-47). Внутреннее имя «DPpass»
        // (экран «О программе», уведомление на своём экране) — @string/app_name.
        manifestPlaceholders["appLabel"] = AppIdentity.STABLE.label
        // Тесты на телефоне (D-75): свой Instrumentation без AndroidX Test (D-34).
        testInstrumentationRunner = "com.dpsmpx.dppass.app.device.DeviceTestRunner"
    }

    buildTypes {
        debug {
            // The experimental Alpine / Zapret2 test APK installs alongside
            // the stable DPpass app rather than requiring an uninstall (and
            // loss of app-private user data) due to the debug certificate.
            if (alpineEnabled) {
                applicationIdSuffix = ".alpine"
                manifestPlaceholders["appLabel"] = "DPpass Alpine (test)"
            }
        }
        release {
            // Не выпуск (CLAUDE.md, «Чего не делать»: выпуск — этап 5): личная
            // сборка для устройств автора (D-35). Подписи в Gradle нет — APK
            // подписывает tools/release/sign_apks.py ключом разработчика из
            // переменных окружения, ключ в демон Gradle не попадает.
            // R8 (D-91): сжатие без переименования и оптимизации; правила JNI —
            // proguard-rules.pro, проверка — check_apk.py --release. Ресурсы
            // сжимаются тоже: имён ресурсов код не собирает (getIdentifier нет),
            // всё нужное видно R8 по ссылкам R.*; assets сжатие не трогает.
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
            // Ярлык сборки (D-114: «DPpass»; случайный — только с dppass.randomIdentity, D-47). Сам
            // applicationId задаётся per-variant ниже (на buildType его ставить
            // нельзя — у типа сборки только applicationIdSuffix).
            manifestPlaceholders["appLabel"] = releaseIdentity.label
        }
    }

    // APK на каждый ABI (D-28) — только по свойству dppass.abiSplit
    // (tools/release/sign_apks.py): отладочная сборка и check_apk.py остаются
    // одним APK со всеми ABI.
    splits {
        abi {
            isEnable = providers.gradleProperty("dppass.abiSplit").map(String::toBoolean).getOrElse(false)
            reset()
            include("arm64-v8a", "armeabi-v7a", "x86_64")
            isUniversalApk = false
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    packaging {
        jniLibs {
            // Библиотеку ядра собирает и проверяет tools/xray/native.py (уже без
            // символов, выровнена по 16 КБ); AGP её не трогает — в APK ровно то,
            // что проверено (check_apk.py).
            keepDebugSymbols += "**/libdppassxray.so"
            // PRoot is an ELF executable shipped as libproot.so; Android must
            // extract it to nativeLibraryDir so execve can run it (API 29+).
            if (alpineEnabled) useLegacyPackaging = true
            keepDebugSymbols += "**/libciadpi.so"

        }
    }

    // Экраны на JVM (D-86): ресурсы и манифест приложения — тестам; наборы тестов
    // телефона (D-75, src/androidTest) идут теми же руками и глазами, что на телефоне.
    if (robolectric) {
        testOptions.unitTests.isIncludeAndroidResources = true
        sourceSets["test"].kotlin.directories += listOf("src/robolectric/kotlin", "src/androidTest/kotlin")
    }

    lint {
        warningsAsErrors = true
        abortOnError = true
        // Модули ядра — тоже под проверкой уровней API Android (minSdk 26).
        checkDependencies = true
        // Новые версии зависимостей проверяются по D-18, а не lint’ом из сети.
        disable += setOf("GradleDependency", "NewerVersionAvailable", "AndroidGradlePluginVersion", "OldTargetApi")
    }
}

kotlin {
    jvmToolchain(21)
    compilerOptions {
        // Предупреждения компилятора — ошибки, как у модулей ядра (build-logic, CLAUDE.md).
        allWarningsAsErrors.set(true)
    }
}

// Ядро Xray в APK (D-25): библиотека собирается задачей на вариант из
// tools/xray тем же go.mod, по которому шаг hostcheck «Xray» проверяет
// компилятор. Без Go или NDK сборка APK падает с причиной.
androidComponents {
    onVariants { variant ->
        // Случайный applicationId личной сборки (D-47) — через variant API:
        // на buildType его ставить нельзя. Отладочная сборка — стабильный id.
        if (variant.buildType == "release") variant.applicationId.set(releaseIdentity.applicationId)

        val name = "xrayNative" + variant.name.replaceFirstChar { it.uppercase() }
        val task = tasks.register<XrayNativeTask>(name) {
            description = "libdppassxray.so для ${variant.name}: tools/xray/native.py android"
            val xray = rootProject.layout.projectDirectory.dir("tools/xray")
            sources.from(
                // Только то, из чего собирается библиотека: пакеты jni и bridge
                // (другие локальные native.py не пускает), модули и сборщик. Тесты
                // Go в неё не входят — их правка не пересобирает ядро трёх ABI.
                xray.asFileTree.matching {
                    include("jni/**/*.go", "bridge/**/*.go", "zapret2/**/*.go", "go.mod", "go.sum", "native.py", "goenv.py")
                    exclude("**/*_test.go")
                },
                rootProject.layout.projectDirectory.file("gradle/libs.versions.toml"),
                // Экспорт JNI сверяется с external fun объекта XrayJni.
                rootProject.layout.projectDirectory.file("engine/src/main/kotlin/com/dpsmpx/dppass/engine/xray/XrayRuntime.kt"),
            )
            script.set(xray.file("native.py"))
            ndkVersion.set(libs.versions.android.ndk)
            // Только эти ABI (D-88): сборка в Termux — -Pdppass.nativeAbis=arm64-v8a; без свойства — все три.
            abis.set(
                providers.gradleProperty("dppass.nativeAbis")
                    .map { v -> v.split(',').map(String::trim).filter(String::isNotEmpty) }
                    .orElse(emptyList()),
            )
            sdkDirectory.set(androidComponents.sdkComponents.sdkDirectory)
        }
        variant.sources.jniLibs?.addGeneratedSourceDirectory(task, XrayNativeTask::outputDir)

        // Набор геоданных (D-27): своим сборщиком из источников каталога, в
        // assets/geodata/ — сжатыми; на устройстве — перенос со сверкой SHA-256.
        val geodata = tasks.register<XrayGeodataTask>("xrayGeodata" + variant.name.replaceFirstChar { it.uppercase() }) {
            description = "набор геоданных для ${variant.name}: tools/xray/geodata.py"
            val xray = rootProject.layout.projectDirectory.dir("tools/xray")
            sources.from(
                // Сборщик набора и его источники; тесты Go набор не меняют.
                xray.asFileTree.matching {
                    include("geodata/**", "go.mod", "go.sum", "geodata.py", "goenv.py")
                    exclude("**/*_test.go")
                },
                rootProject.layout.projectDirectory.file("gradle/libs.versions.toml"),
                rootProject.layout.projectDirectory.file("docs/PROVENANCE.md"),
            )
            script.set(xray.file("geodata.py"))
        }
        variant.sources.assets?.addGeneratedSourceDirectory(geodata, XrayGeodataTask::outputDir)

        // Уведомления о сторонних компонентах (D-43): из матрицы лицензий и лицензий модулей Go.
        val notices = tasks.register<LegalNoticesTask>("legalNotices" + variant.name.replaceFirstChar { it.uppercase() }) {
            description = "уведомления о лицензиях для ${variant.name}: tools/legal/notices.py"
            sources.from(
                rootProject.layout.projectDirectory.file("docs/legal/THIRD_PARTY_MATRIX.md"),
                rootProject.layout.projectDirectory.file("tools/xray/go.mod"),
                rootProject.layout.projectDirectory.file("tools/xray/go.sum"),
                rootProject.layout.projectDirectory.file("tools/legal/notices.py"),
            )
            script.set(rootProject.layout.projectDirectory.file("tools/legal/notices.py"))
        }
        variant.sources.assets?.addGeneratedSourceDirectory(notices, LegalNoticesTask::outputDir)
    }
}


// Opt-in Alpine runtime: the same pinned Termux PRoot sources and Alpine
// minirootfs as DPmetaApp/dpai. No unverified APK binaries or npm downloads.
if (alpineEnabled) {
    val alpineFiles = tasks.register("alpineFiles") {
        val cache = File(gradle.gradleUserHomeDir, "caches/dppass-alpine")
        val jni = layout.buildDirectory.dir("generated/alpine-jni")
        val assets = layout.buildDirectory.dir("generated/alpine-assets")
        val builder = rootProject.file("tools/alpine/build-proot.sh")
        val xrayToolDir = rootProject.file("tools/xray")
        val compat = rootProject.file("tools/alpine/proot-musl-compat.h")
        val ndk = androidComponents.sdkComponents.ndkDirectory
        val url = "https://dl-cdn.alpinelinux.org/alpine/v3.24/releases/aarch64/alpine-minirootfs-3.24.3-aarch64.tar.gz"
        val pin = "4d3f80afaebd447c5591a63a73bde380a149fe8b2d85488cafabb2ff97551f50"
        inputs.files(builder, compat, rootProject.file("tools/xray/go.mod"), rootProject.file("tools/xray/go.sum"))
        inputs.files(rootProject.fileTree("tools/xray/zapret2") { include("**/*.go"); exclude("**/*_test.go") })
        inputs.files(rootProject.fileTree("tools/xray/cmd/zapret2-alpine") { include("**/*.go") })
        inputs.property("rootfs-url", url)
        inputs.property("rootfs-sha256", pin)
        outputs.dirs(jni, assets)
        doLast {
            fun sha256(bytes: ByteArray) = MessageDigest.getInstance("SHA-256")
                .digest(bytes).joinToString("") { "%02x".format(it) }
            cache.mkdirs()
            val archive = File(cache, url.substringAfterLast('/'))
            if (!archive.exists()) {
                val partial = File(cache, archive.name + ".part")
                URI(url).toURL().openStream().use { source ->
                    partial.outputStream().use { dest -> source.copyTo(dest) }
                }
                check(partial.renameTo(archive)) { "failed to cache Alpine rootfs" }
            }
            val data = archive.readBytes()
            check(sha256(data) == pin) { "Alpine minirootfs checksum mismatch" }
            val built = temporaryDir.resolve("proot-aarch64")
            val proc = ProcessBuilder("sh", builder.absolutePath, "aarch64",
                built.absolutePath, cache.resolve("proot").absolutePath)
                .redirectErrorStream(true)
                .apply { environment()["NDK"] = ndk.get().asFile.absolutePath }
                .start()
            val log = proc.inputStream.bufferedReader().use { it.readText() }
            check(proc.waitFor() == 0) { "Termux PRoot build failed:\n" + log.takeLast(4000) }
            val p = File(built, "proot").readBytes()
            val l = File(built, "loader").readBytes()
            fun isAarch64Elf(b: ByteArray) = b.size > 64 && b[0] == 127.toByte() &&
                b[1] == 'E'.code.toByte() && b[4] == 2.toByte() &&
                ByteBuffer.wrap(b, 18, 2).order(ByteOrder.LITTLE_ENDIAN).short.toInt() == 183
            check(isAarch64Elf(p) && isAarch64Elf(l)) { "unexpected proot/loader ELF ABI" }
            val out = File(jni.get().asFile, "arm64-v8a")
            out.mkdirs()
            File(out, "libproot.so").writeBytes(p)
            File(out, "libproot-loader.so").writeBytes(l)
            val asset = File(assets.get().asFile, "alpine")
            asset.mkdirs()
            File(asset, "rootfs.tgz").writeBytes(data)
            // One portable strategy planner in Alpine; Android's VpnService
            // remains the protected network socket/packet transport.
            val engineOut = File(temporaryDir, "zapret2-alpine")
            val engine = ProcessBuilder("go", "build", "-trimpath", "-buildvcs=false",
                "-ldflags=-s -w -buildid=", "-o", engineOut.absolutePath,
                "./cmd/zapret2-alpine")
                .directory(xrayToolDir)
                .redirectErrorStream(true)
                .apply {
                    environment()["GOOS"] = "linux"
                    environment()["GOARCH"] = "arm64"
                    environment()["CGO_ENABLED"] = "0"
                }.start()
            val engineLog = engine.inputStream.bufferedReader().use { it.readText() }
            check(engine.waitFor() == 0) { "Alpine strategy engine compile failed:\n" + engineLog.takeLast(4000) }
            val executable = engineOut.readBytes()
            check(isAarch64Elf(executable)) { "Alpine strategy engine is not ARM64 ELF" }
            File(asset, "zapret2-runtime.bin").writeBytes(executable)
            File(asset, "zapret2-runtime.sha256").writeText(sha256(executable) + "\n")
        }
    }
    androidComponents {
        onVariants { variant ->
            variant.sources.assets?.addStaticSourceDirectory(layout.buildDirectory.dir("generated/alpine-assets").get().asFile.path)
            variant.sources.jniLibs?.addStaticSourceDirectory(layout.buildDirectory.dir("generated/alpine-jni").get().asFile.path)
        }
    }
    tasks.matching {
        (it.name.startsWith("merge") || it.name.startsWith("package") || it.name.startsWith("copy")) &&
            (it.name.endsWith("Assets") || it.name.contains("JniLib") || it.name.endsWith("NativeLibs")) ||
            it.name.contains("lint", ignoreCase = true)
    }.configureEach { dependsOn(alpineFiles) }
}

dependencies {
    implementation(project(":connection"))
    implementation(libs.kotlinx.coroutines.core)
    // QR с картинки (D-65): распознаёт ZXing core, только в оболочке.
    implementation(libs.zxing.core)

    // Логика экранов без Android (D-34) — тестами на хосте, как модули ядра.
    // Модулям ядра вариант JUnit 5 у kotlin-test выбирает плагин kotlin-jvm; у
    // встроенного в AGP Kotlin этого нет — вариант задан явно (тот же артефакт).
    // kotlin("test") здесь — строка координат (тип Any): нужен явный тип для блока настройки.
    testImplementation(kotlin("test") as String) {
        capabilities { requireCapability("org.jetbrains.kotlin:kotlin-test-framework-junit5") }
    }
    testImplementation(platform(libs.junit.bom))
    testImplementation(libs.junit.jupiter)
    testRuntimeOnly(libs.junit.platform.launcher)
    if (robolectric) {
        testImplementation(libs.robolectric)
        testImplementation(libs.junit4)
        testRuntimeOnly(libs.junit.vintage.engine)
        robolectricImages.getValue(26)(libs.robolectric.android.all.api26)
        robolectricImages.getValue(29)(libs.robolectric.android.all.api29)
        robolectricImages.getValue(36)(libs.robolectric.android.all)
    }
}

// Образы всех API — одной задачей: суммы для verification-metadata.xml (update_verification.sh, D-108).
if (robolectric) {
    tasks.register("robolectricImages") {
        description = "Скачивает и сверяет образы Android для Robolectric всех API (D-108)"
        val images: List<FileCollection> = robolectricImages.values.map { it.incoming.artifacts.artifactFiles }
        inputs.files(images)
        doLast { images.forEach { it.files } }
    }
}

tasks.withType<Test>().configureEach {
    useJUnitPlatform()
    // Тест, который JUnit не смог запустить, — ошибка прогона (как в модулях ядра).
    systemProperty("junit.platform.discovery.issue.severity.critical", "WARNING")
    if (robolectric) {
        // Robolectric ничего не скачивает сам: образ уже проверен Gradle (D-86).
        val image: FileCollection = robolectricImages.getValue(robolectricSdk).incoming.artifacts.artifactFiles
        inputs.files(image)
        systemProperty("robolectric.offline", "true")
        // Тесты объявляют все API (@Config); идёт только выбранное.
        systemProperty("robolectric.enabledSdks", robolectricSdk.toString())
        // Образ Android 16 заводит общую память через внутренности FileDescriptor JDK — только в JVM тестов.
        jvmArgs("--add-exports=java.base/jdk.internal.access=ALL-UNNAMED")
        jvmArgumentProviders.add(CommandLineArgumentProvider { listOf("-Drobolectric.dependency.dir=" + image.singleFile.parentFile.path) })
        // Тесты путей (D-90) действуют: настоящее ядро Xray проверяет конфигурацию, как на телефоне.
        val lib = xrayHostLib
        inputs.files(lib).withPropertyName("xrayHostLib").optional()
        jvmArgumentProviders.add(CommandLineArgumentProvider { listOfNotNull(lib.orNull?.let { "-Djava.library.path=" + it.parentFile.path }) })
        // Состояние приложения — в объектах процесса (AppGraph, TunnelState): у каждого класса тестов свой процесс.
        forkEvery = 1
    }
}
