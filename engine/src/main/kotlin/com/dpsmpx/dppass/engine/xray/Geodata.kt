package com.dpsmpx.dppass.engine.xray

import com.dpsmpx.dppass.core.Checksums
import com.dpsmpx.dppass.core.Json
import com.dpsmpx.dppass.core.JsonArray
import com.dpsmpx.dppass.core.JsonNumber
import com.dpsmpx.dppass.core.JsonObject
import com.dpsmpx.dppass.core.JsonParseException
import com.dpsmpx.dppass.core.JsonString
import com.dpsmpx.dppass.core.JsonValue
import com.dpsmpx.dppass.diagnostics.DiagCode
import com.dpsmpx.dppass.diagnostics.Diagnostic
import com.dpsmpx.dppass.diagnostics.Outcome
import java.io.File
import java.io.IOException
import java.io.InputStream
import java.nio.file.AtomicMoveNotSupportedException
import java.nio.file.Files
import java.nio.file.StandardCopyOption
import java.security.MessageDigest

/** Файл набора геоданных: имя без пути, SHA-256 и размер. */
data class GeodataFile(val name: String, val sha256: String, val size: Long)

/**
 * Оглавление набора геоданных ядра (D-27): `manifest.json`, который
 * пишет сборщик `tools/xray/geodata` (формат `dppass.geodata`, версия 1).
 * Источники — для отчёта; файлы — для сверки при переносе; коды — для
 * сверки конфигурации с набором.
 */
data class GeodataManifest(
    val dlcVersion: String,
    val dlcCommit: String,
    val dbipRelease: String,
    val files: List<GeodataFile>,
    /** Коды geoip в нижнем регистре, как в конфигурации. */
    val geoIp: Set<String>,
    /** Коды geosite → атрибуты, которые встречаются в списке. */
    val geoSite: Map<String, Set<String>>,
) {
    /** Из чего собран набор — строка отчёта (D-27). */
    val summary: String get() = "dlc $dlcCommit, DB-IP $dbipRelease"

    companion object {
        const val FORMAT: String = "dppass.geodata"
        const val FORMAT_VERSION: Int = 1
        const val FILE: String = "manifest.json"

        /** Файлы, без которых набор — не набор: их ищет Xray (common/geodata). */
        val REQUIRED: Set<String> = setOf("geoip.dat", "geosite.dat")

        // Имя файла — без каталогов и без точки в начале: оглавление не
        // указывает установщику, куда писать за пределами набора.
        private val NAME = Regex("[A-Za-z0-9_-][A-Za-z0-9._-]{0,63}")
        private val SHA256 = Regex("[0-9a-f]{64}")

        fun parse(text: String): Outcome<GeodataManifest> {
            val root = try {
                Json.parse(text)
            } catch (e: JsonParseException) {
                return invalid("оглавление набора — не JSON: ${e.reason} (строка ${e.line})")
            }
            return try {
                Outcome.Success(read(root))
            } catch (e: IllegalArgumentException) {
                invalid("оглавление набора: ${e.message}")
            }
        }

        private fun invalid(message: String) = Outcome.failure(DiagCode.GEODATA_UNAVAILABLE, message)

        private fun read(root: JsonValue): GeodataManifest {
            val o = root.obj("оглавление")
            require(o.str("format") == FORMAT) { "формат не $FORMAT" }
            val version = (o["format_version"] as? JsonNumber)?.toIntOrNull()
            require(version == FORMAT_VERSION) { "версия формата $version, поддерживается $FORMAT_VERSION" }
            val sources = o["sources"].obj("sources")
            val dlc = sources["dlc"].obj("sources.dlc")
            val dbip = sources["dbip"].obj("sources.dbip")
            val files = o["files"].arr("files").map { v ->
                val f = v.obj("files[]")
                val name = f.str("name")
                require(NAME.matches(name)) { "имя файла «$name» — не имя файла набора" }
                val sha = f.str("sha256")
                require(SHA256.matches(sha)) { "$name: SHA-256 не из 64 шестнадцатеричных цифр" }
                val size = (f["size"] as? JsonNumber)?.toLongOrNull()
                require(size != null && size >= 0) { "$name: размер не число" }
                GeodataFile(name, sha, size)
            }
            require(files.map { it.name }.toSet().size == files.size) { "имена файлов повторяются" }
            require(files.map { it.name }.containsAll(REQUIRED + "NOTICE.txt")) { "нет ${REQUIRED + "NOTICE.txt"}" }
            require(files.none { it.name == FILE }) { "оглавление не описывает само себя" }
            val geoIp = o["geoip"].arr("geoip").map { it.string("geoip[]") }.toSet()
            val geoSite = o["geosite"].obj("geosite").fields.mapValues { (code, attrs) ->
                attrs.arr("geosite.$code").map { it.string("geosite.$code[]") }.toSet()
            }
            return GeodataManifest(dlc.str("version"), dlc.str("commit"), dbip.str("release"), files, geoIp, geoSite)
        }

        private fun JsonValue?.obj(what: String): JsonObject = requireNotNull(this as? JsonObject) { "$what — не объект" }
        private fun JsonValue?.arr(what: String): List<JsonValue> = requireNotNull(this as? JsonArray) { "$what — не массив" }.items
        private fun JsonValue?.string(what: String): String = requireNotNull(this as? JsonString) { "$what — не строка" }.value
        private fun JsonObject.str(key: String): String = this[key].string(key)
    }
}

/**
 * Сверка кодов geoip/geosite конфигурации с набором геоданных ядра (D-27):
 * код, которого нет в наборе, — отказ компиляции с путём правила, а не
 * условие, которое молча не выполняется (D-05).
 */
sealed interface GeodataCodes {
    /** Не сверять: набор задаёт тот, кто проверяет конфигурацию ядром (хост, `cli`, эталоны). */
    data object Unchecked : GeodataCodes

    /** Набор установлен: коды и атрибуты — из его оглавления. */
    data class Installed(val manifest: GeodataManifest) : GeodataCodes

    /** Набора нет: любое правило с geoip/geosite — отказ с этой причиной. */
    data class Missing(val reason: String) : GeodataCodes
}

/** Откуда берётся набор: на Android — assets APK (`geodata/…`). */
fun interface GeodataSource {
    /** Поток файла набора по имени; нет файла — [IOException]. */
    @Throws(IOException::class)
    fun open(name: String): InputStream
}

/** Установленный набор: каталог для ядра (`SetAssetDir`) и его оглавление. */
data class InstalledGeodata(val dir: File, val manifest: GeodataManifest, val installedNow: Boolean)

/**
 * Перенос набора геоданных из APK в [root] (`noBackupFilesDir/geodata`,
 * D-27): ядро читает файлы с диска, а не из APK.
 *
 * Набор ставится в каталог с именем по SHA-256 своего оглавления: другой
 * набор (новая версия приложения) — другой каталог. Перенос атомарный:
 * файлы пишутся во временный каталог, каждый сверяется с оглавлением по
 * SHA-256 и размеру и сбрасывается на диск (D-19), и только потом каталог
 * переименовывается в постоянный. Поэтому каталог набора либо есть
 * целиком и сверенный, либо его нет. Прерванный перенос оставляет только
 * временный каталог, и его удаляет следующий запуск. Старые наборы
 * удаляются после установки нового.
 *
 * Установленный набор не перечитывается при каждом запуске: каталог
 * появляется только после сверки, а данные приложения (`noBackupFilesDir`)
 * другим приложениям недоступны.
 */
class GeodataInstaller(private val source: GeodataSource, private val root: File) {
    fun install(): Outcome<InstalledGeodata> {
        val manifestBytes = try {
            source.open("$ASSETS/${GeodataManifest.FILE}").use { it.readBytes() }
        } catch (e: IOException) {
            return unavailable("в приложении нет набора геоданных ($ASSETS/${GeodataManifest.FILE})", e)
        }
        val manifest = when (val m = GeodataManifest.parse(manifestBytes.toString(Charsets.UTF_8))) {
            is Outcome.Failure -> return m
            is Outcome.Success -> m.value
        }
        val id = Checksums.sha256(manifestBytes).take(ID_LENGTH)
        val target = File(root, id)
        val placed = File(target, GeodataManifest.FILE)
        val installedNow = try {
            if (placed.isFile && placed.readBytes().contentEquals(manifestBytes)) {
                false
            } else {
                place(manifest, manifestBytes, id, target)?.let { return it }
                true
            }
        } catch (e: IOException) {
            return unavailable("набор геоданных не перенесён в ${root.name}/$id", e)
        }
        removeOthers(keep = id)
        return Outcome.Success(InstalledGeodata(target, manifest, installedNow))
    }

    /** Перенос во временный каталог со сверкой и переименование; null — успех. */
    private fun place(manifest: GeodataManifest, manifestBytes: ByteArray, id: String, target: File): Outcome.Failure? {
        val tmp = File(root, ".$id$TMP")
        tmp.deleteRecursively()
        if (!tmp.mkdirs()) throw IOException("не создан каталог ${tmp.name}")
        for (f in manifest.files) {
            val digest = MessageDigest.getInstance("SHA-256")
            var size = 0L
            File(tmp, f.name).outputStream().use { out ->
                source.open("$ASSETS/${f.name}").use { input ->
                    val buf = ByteArray(BUFFER)
                    while (true) {
                        val n = input.read(buf)
                        if (n < 0) break
                        digest.update(buf, 0, n)
                        out.write(buf, 0, n)
                        size += n
                    }
                }
                out.fd.sync()
            }
            val sha = digest.digest().toHex()
            if (sha != f.sha256 || size != f.size) {
                tmp.deleteRecursively()
                return Outcome.failure(
                    DiagCode.GEODATA_UNAVAILABLE,
                    "файл набора ${f.name} не совпал с оглавлением: SHA-256 ${sha.take(12)}…, размер $size " +
                        "(ожидалось ${f.sha256.take(12)}…, ${f.size})",
                )
            }
        }
        // Оглавление — последним: по нему следующий запуск узнаёт установленный набор.
        File(tmp, GeodataManifest.FILE).outputStream().use { out ->
            out.write(manifestBytes)
            out.fd.sync()
        }
        target.deleteRecursively()
        try {
            Files.move(tmp.toPath(), target.toPath(), StandardCopyOption.ATOMIC_MOVE)
        } catch (e: AtomicMoveNotSupportedException) {
            tmp.deleteRecursively()
            return Outcome.failure(Diagnostic.fromThrowable(DiagCode.GEODATA_UNAVAILABLE, "файловая система не умеет атомарное переименование", e))
        }
        return null
    }

    /** Старые наборы и прерванные переносы — только то, что похоже на свои каталоги. */
    private fun removeOthers(keep: String) {
        root.listFiles()?.forEach { f ->
            val name = f.name.removePrefix(".").removeSuffix(TMP)
            if (name != keep && OWN.matches(name) && f.isDirectory) f.deleteRecursively()
        }
    }

    private fun unavailable(message: String, e: Exception) = Outcome.failure(Diagnostic.fromThrowable(DiagCode.GEODATA_UNAVAILABLE, message, e))

    private companion object {
        const val ASSETS = "geodata"
        const val ID_LENGTH = 16
        const val TMP = ".tmp"
        const val BUFFER = 64 * 1024
        val OWN = Regex("[0-9a-f]{$ID_LENGTH}")

        fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it.toInt() and 0xff) }
    }
}
