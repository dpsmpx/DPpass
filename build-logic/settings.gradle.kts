// Kotlin DSL toolchain can depend on Kotlin artifacts hosted by Maven Central.
// Plugin Portal alone occasionally returns incomplete Kotlin transitive POMs.
pluginManagement {
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
    }
}

// Сборка convention-плагинов DPpass: общие правила модулей в одном месте.
dependencyResolutionManagement {
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
    }
    versionCatalogs {
        create("libs") {
            from(files("../gradle/libs.versions.toml"))
        }
    }
}

rootProject.name = "build-logic"
