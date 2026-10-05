// Android-приложение DPpass: оболочка над DPpassCore (D-02, D-17).
// Подключается, только если найден Android SDK (settings.gradle.kts).
import com.dpsmpx.dppass.build.XrayGeodataTask
import com.dpsmpx.dppass.build.XrayNativeTask

plugins {
    id("dppass.android-app")
}

android {
    namespace = "com.dpsmpx.dppass"
    compileSdk = libs.versions.android.compileSdk.get().toInt()

    defaultConfig {
        // applicationId фиксируется окончательно перед первым выпуском (D-01,
        // отложенное решение «название»): после выпуска его не сменить.
        applicationId = "com.dpsmpx.dppass"
        minSdk = libs.versions.android.minSdk.get().toInt()
        targetSdk = libs.versions.android.targetSdk.get().toInt()
        versionCode = 1
        versionName = "0.0.1-dev"
    }

    buildTypes {
        release {
            // Подпись и R8 — к этапу выпуска (ROADMAP, этап 5); до него
            // релизная сборка не публикуется (CLAUDE.md, «Чего не делать»).
            isMinifyEnabled = false
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
    }
}

dependencies {
    implementation(project(":connection"))
    implementation(libs.kotlinx.coroutines.core)
}
