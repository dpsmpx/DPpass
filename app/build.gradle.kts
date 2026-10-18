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

android {
    namespace = "com.dpsmpx.dppass"
    compileSdk = libs.versions.android.compileSdk.get().toInt()

    defaultConfig {
        // Личность по умолчанию — стабильная (отладка, проверки); release её
        // переопределяет (D-47). Публичный applicationId фиксируется перед
        // выпуском (D-01, этап 5) — рандомизация туда не идёт.
        applicationId = AppIdentity.STABLE.applicationId
        minSdk = libs.versions.android.minSdk.get().toInt()
        targetSdk = libs.versions.android.targetSdk.get().toInt()
        versionCode = 82
        versionName = "0.7.12-dev"
        // Ярлык приложения — через placeholder: стабильный для отладки,
        // случайный для личного release (D-47). Внутреннее имя «DPpass»
        // (экран «О программе», уведомление на своём экране) — @string/app_name.
        manifestPlaceholders["appLabel"] = AppIdentity.STABLE.label
    }

    buildTypes {
        release {
            // Не выпуск (CLAUDE.md, «Чего не делать»: выпуск — этап 5): личная
            // сборка для устройств автора (D-35). Без R8; подписи в Gradle нет —
            // APK подписывает tools/release/sign_apks.py ключом разработчика из
            // переменных окружения, ключ в демон Gradle не попадает.
            isMinifyEnabled = false
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
                xray.asFileTree.matching { include("**/*.go", "go.mod", "go.sum", "*.py") },
                rootProject.layout.projectDirectory.file("gradle/libs.versions.toml"),
                // Экспорт JNI сверяется с external fun объекта XrayJni.
                rootProject.layout.projectDirectory.file("engine/src/main/kotlin/com/dpsmpx/dppass/engine/xray/XrayRuntime.kt"),
            )
            script.set(xray.file("native.py"))
            ndkVersion.set(libs.versions.android.ndk)
            sdkDirectory.set(androidComponents.sdkComponents.sdkDirectory)
        }
        variant.sources.jniLibs?.addGeneratedSourceDirectory(task, XrayNativeTask::outputDir)

        // Набор геоданных (D-27): своим сборщиком из источников каталога, в
        // assets/geodata/ — сжатыми; на устройстве — перенос со сверкой SHA-256.
        val geodata = tasks.register<XrayGeodataTask>("xrayGeodata" + variant.name.replaceFirstChar { it.uppercase() }) {
            description = "набор геоданных для ${variant.name}: tools/xray/geodata.py"
            val xray = rootProject.layout.projectDirectory.dir("tools/xray")
            sources.from(
                xray.asFileTree.matching { include("geodata/**", "go.mod", "go.sum", "*.py") },
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
}

tasks.withType<Test>().configureEach {
    useJUnitPlatform()
    // Тест, который JUnit не смог запустить, — ошибка прогона (как в модулях ядра).
    systemProperty("junit.platform.discovery.issue.severity.critical", "WARNING")
}
