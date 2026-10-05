package com.dpsmpx.dppass.build

import org.gradle.api.DefaultTask
import org.gradle.api.file.ConfigurableFileCollection
import org.gradle.api.file.DirectoryProperty
import org.gradle.api.file.RegularFileProperty
import org.gradle.api.tasks.InputFiles
import org.gradle.api.tasks.Internal
import org.gradle.api.tasks.OutputDirectory
import org.gradle.api.tasks.PathSensitive
import org.gradle.api.tasks.PathSensitivity
import org.gradle.api.tasks.TaskAction
import org.gradle.process.ExecOperations
import javax.inject.Inject

/**
 * Набор геоданных ядра для APK (D-27, D-31): `tools/xray/geodata.py`
 * собирает `geoip.dat`, `geosite.dat`, `NOTICE.txt` и `manifest.json` из
 * источников, закреплённых в каталоге, со сверкой сумм из PROVENANCE.
 * Результат — `geodata/…` в [outputDir], его берёт `sources.assets`
 * варианта. В APK файлы лежат сжатыми; приложение переносит их в
 * `noBackupFilesDir` со сверкой SHA-256 (`engine.xray.GeodataInstaller`).
 *
 * Без Go задача падает: APK без набора отвергал бы любые правила с
 * geoip/geosite, а собранный молча без него скрыл бы это. Не кешируется:
 * dlc приходит Go-модулем вне входов задачи (его сумму сверяет скрипт).
 */
abstract class XrayGeodataTask : DefaultTask() {
    /** Сборщик, источники, скрипт, каталог и PROVENANCE: изменение любого — пересборка. */
    @get:InputFiles
    @get:PathSensitive(PathSensitivity.RELATIVE)
    abstract val sources: ConfigurableFileCollection

    @get:Internal
    abstract val script: RegularFileProperty

    @get:OutputDirectory
    abstract val outputDir: DirectoryProperty

    @get:Inject
    abstract val exec: ExecOperations

    @TaskAction
    fun build() {
        val out = outputDir.get().asFile
        out.deleteRecursively()
        out.mkdirs()
        exec.exec {
            commandLine("python3", script.get().asFile.path, "--out", out.path)
        }
    }
}
