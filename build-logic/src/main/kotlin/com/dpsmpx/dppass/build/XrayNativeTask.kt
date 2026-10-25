package com.dpsmpx.dppass.build

import org.gradle.api.DefaultTask
import org.gradle.api.GradleException
import org.gradle.api.file.ConfigurableFileCollection
import org.gradle.api.file.DirectoryProperty
import org.gradle.api.file.RegularFileProperty
import org.gradle.api.provider.ListProperty
import org.gradle.api.provider.Property
import org.gradle.api.tasks.Input
import org.gradle.api.tasks.InputFiles
import org.gradle.api.tasks.Internal
import org.gradle.api.tasks.OutputDirectory
import org.gradle.api.tasks.PathSensitive
import org.gradle.api.tasks.PathSensitivity
import org.gradle.api.tasks.TaskAction
import org.gradle.process.ExecOperations
import javax.inject.Inject

/**
 * Библиотека ядра `libdppassxray.so` для APK (D-25): `tools/xray/native.py
 * android` — NDK версии из каталога, три ABI, выравнивание 16 КБ, сверка
 * экспорта JNI с `XrayJni`. Результат — `<ABI>/libdppassxray.so` в
 * [outputDir], его берёт `sources.jniLibs` варианта.
 *
 * Без Go или NDK задача падает: APK без ядра бесполезен, а собранный
 * молча без него скрыл бы это (D-25). Не кешируется: результат зависит от
 * NDK и toolchain Go вне входов задачи; повторную сборку экономит кеш Go.
 *
 * [abis] пусто — все три ABI. Иначе — только названные (D-88): сборка в
 * Termux на телефоне автора — `-Pdppass.nativeAbis=arm64-v8a`, clang там
 * падал на `armeabi-v7a`. Такой APK — только для того телефона:
 * `check_apk.py` ждёт три ABI.
 */
abstract class XrayNativeTask : DefaultTask() {
    /** Исходники моста и скрипт сборки: изменение любого — пересборка. */
    @get:InputFiles
    @get:PathSensitive(PathSensitivity.RELATIVE)
    abstract val sources: ConfigurableFileCollection

    @get:Internal
    abstract val script: RegularFileProperty

    @get:Input
    abstract val ndkVersion: Property<String>

    @get:Input
    abstract val abis: ListProperty<String>

    @get:Internal
    abstract val sdkDirectory: DirectoryProperty

    @get:OutputDirectory
    abstract val outputDir: DirectoryProperty

    @get:Inject
    abstract val exec: ExecOperations

    @TaskAction
    fun build() {
        val out = outputDir.get().asFile
        out.deleteRecursively()
        out.mkdirs()
        val only = abiArgs(abis.get())
        exec.exec {
            commandLine(listOf("python3", script.get().asFile.path, "android", "--out", out.path) + only)
            environment("ANDROID_HOME", sdkDirectory.get().asFile.path)
            environment("ANDROID_SDK_ROOT", sdkDirectory.get().asFile.path)
        }
    }

    companion object {
        /** ABI APK (D-28) — те же, что у `native.py android`. */
        val ALL: List<String> = listOf("arm64-v8a", "armeabi-v7a", "x86_64")

        /** `--abi` для `native.py`: пусто — все; неизвестный ABI или повтор — отказ сборки, а не APK без ядра. */
        fun abiArgs(abis: List<String>): List<String> {
            val unknown = abis.filterNot { it in ALL }
            if (unknown.isNotEmpty()) throw GradleException("dppass.nativeAbis: неизвестные ABI ${unknown.joinToString()} — бывают ${ALL.joinToString()}")
            if (abis.distinct().size != abis.size) throw GradleException("dppass.nativeAbis: ABI повторяется — ${abis.joinToString()}")
            return abis.flatMap { listOf("--abi", it) }
        }
    }
}
