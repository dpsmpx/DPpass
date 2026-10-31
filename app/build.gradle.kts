// Android-приложение DPpass: оболочка над DPpassCore (D-02, D-17).
// Подключается, только если найден Android SDK (settings.gradle.kts).
import com.dpsmpx.dppass.build.AppIdentity
import com.dpsmpx.dppass.build.LegalNoticesTask
import com.dpsmpx.dppass.build.XrayGeodataTask
import com.dpsmpx.dppass.build.XrayNativeTask

plugins {
    id("dppass.android-app")
}

// Личность устанавливаемого приложения (D-47). Пространство имён кода —
// всегда `com.dpsmpx.dppass` (ниже `namespace`): меняется только личность.
//   * отладочная сборка и проверки — стабильная личность (детерминизм);
//   * личная сборка release — случайные applicationId и ярлык, чтобы по
//     имени пакета и ярлыку приложение не отличалось от обычного.
// Зерно `dppass.identitySeed` делает личную сборку воспроизводимой.
val stableIdentity = providers.gradleProperty("dppass.stableIdentity").map(String::toBoolean).getOrElse(false)
val identitySeed = AppIdentity.seedOf(providers.gradleProperty("dppass.identitySeed").orNull)
val releaseIdentity = if (stableIdentity) AppIdentity.STABLE else AppIdentity.random(identitySeed)

// Тесты экранов на JVM (D-86): Robolectric — только по свойству dppass.robolectric
// (шаг проверки «Android: экраны на JVM»). Обычная сборка, в том числе в Termux,
// его не тянет: «Android целиком» — 213 МБ.
val robolectric = providers.gradleProperty("dppass.robolectric").isPresent

// Ядро Xray в тестах путей на JVM (D-90): библиотека моста для хоста — та же, что у XrayJniTest.
val repoRoot: File = rootDir
val xrayHostLib: Provider<File> = providers.gradleProperty("dppass.xray.lib").map { repoRoot.resolve(it).absoluteFile }

/** Образ «Android целиком» для Robolectric — через Gradle, с проверкой суммы (аудит A-7), а не загрузкой из теста. */
val robolectricAndroid: Configuration by configurations.creating {
    isCanBeConsumed = false
    isTransitive = false
}

android {
    namespace = "com.dpsmpx.dppass"
    compileSdk = libs.versions.android.compileSdk.get().toInt()

    defaultConfig {
        // Личность по умолчанию — стабильная (отладка, проверки); release её
        // переопределяет (D-47). Публичный applicationId — com.dpsmpx.dppass
        // (D-103) — рандомизация туда не идёт.
        applicationId = AppIdentity.STABLE.applicationId
        minSdk = libs.versions.android.minSdk.get().toInt()
        targetSdk = libs.versions.android.targetSdk.get().toInt()
        versionCode = 119
        versionName = "0.7.49-dev"
        // Ярлык приложения — через placeholder: стабильный для отладки,
        // случайный для личного release (D-47). Внутреннее имя «DPpass»
        // (экран «О программе», уведомление на своём экране) — @string/app_name.
        manifestPlaceholders["appLabel"] = AppIdentity.STABLE.label
        // Тесты на телефоне (D-75): свой Instrumentation без AndroidX Test (D-34).
        testInstrumentationRunner = "com.dpsmpx.dppass.app.device.DeviceTestRunner"
    }

    buildTypes {
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
            // Случайный ярлык личной сборки (D-47): не выдаёт назначение. Сам
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
                    include("jni/**/*.go", "bridge/**/*.go", "go.mod", "go.sum", "native.py", "goenv.py")
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
        robolectricAndroid(libs.robolectric.android.all)
    }
}

tasks.withType<Test>().configureEach {
    useJUnitPlatform()
    // Тест, который JUnit не смог запустить, — ошибка прогона (как в модулях ядра).
    systemProperty("junit.platform.discovery.issue.severity.critical", "WARNING")
    if (robolectric) {
        // Robolectric ничего не скачивает сам: образ уже проверен Gradle (D-86).
        val image: FileCollection = robolectricAndroid.incoming.artifacts.artifactFiles
        inputs.files(image)
        systemProperty("robolectric.offline", "true")
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
