package com.dpsmpx.dppass.engine.xray

import com.dpsmpx.dppass.core.Checksums
import com.dpsmpx.dppass.core.Json
import com.dpsmpx.dppass.core.JsonArray
import com.dpsmpx.dppass.core.JsonString
import com.dpsmpx.dppass.diagnostics.DiagCode
import com.dpsmpx.dppass.diagnostics.Outcome
import java.io.ByteArrayInputStream
import java.io.File
import java.io.FileNotFoundException
import java.io.IOException
import java.io.InputStream
import java.nio.file.Files
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertTrue

/**
 * Набор геоданных на устройстве (D-27): оглавление от сборщика
 * `tools/xray/geodata` и перенос из APK со сверкой. Данные — синтетические
 * байты: установщику всё равно, что внутри файлов.
 */
class GeodataTest {
    private fun attrSets(vararg sets: List<String>): JsonArray = JsonArray(sets.map { set -> JsonArray(set.map(::JsonString)) })

    private fun manifestJson(
        files: Map<String, ByteArray>,
        release: String = "2026-01",
        geosite: JsonArray = attrSets(listOf("ads")),
    ): String = Json.write(
        Json.obj(
            "format" to JsonString("dppass.geodata"),
            "format_version" to Json.num(2),
            "sources" to Json.obj(
                "dlc" to Json.obj(
                    "module" to JsonString("dlc"),
                    "version" to JsonString("v0.0.0-20260101000000-0123456789ab"),
                    "commit" to JsonString("0123456789ab"),
                ),
                "dbip" to Json.obj("release" to JsonString(release), "sha256" to JsonString("0".repeat(64))),
            ),
            "files" to JsonArray(
                files.map { (name, bytes) ->
                    Json.obj("name" to JsonString(name), "sha256" to JsonString(Checksums.sha256(bytes)), "size" to Json.num(bytes.size.toLong()))
                },
            ),
            "geoip" to JsonArray(listOf(JsonString("aa"), JsonString("private"))),
            "geosite" to Json.obj("example-a" to geosite),
        ),
    )

    private val files = mapOf(
        "geoip.dat" to ByteArray(200_000) { (it % 251).toByte() },
        "geosite.dat" to "synthetic geosite".toByteArray(),
        "NOTICE.txt" to "IP Geolocation by DB-IP".toByteArray(),
    )

    /** Assets: имя → байты; [broken] — файл, чтение которого обрывается. */
    private class Assets(val content: Map<String, ByteArray>, val broken: String? = null) : GeodataSource {
        override fun open(name: String): InputStream {
            val bytes = content[name] ?: throw FileNotFoundException(name)
            if (name == broken) {
                return object : InputStream() {
                    var left = bytes.size / 2
                    override fun read(): Int = if (left-- > 0) 0 else throw IOException("чтение оборвалось")
                }
            }
            return ByteArrayInputStream(bytes)
        }
    }

    private fun assets(set: Map<String, ByteArray> = files, manifest: String = manifestJson(files), broken: String? = null) =
        Assets(set.mapKeys { "geodata/${it.key}" } + ("geodata/manifest.json" to manifest.toByteArray()), broken)

    private fun root(): File = Files.createTempDirectory("dppass-geodata").toFile()

    private fun names(dir: File): List<String> = dir.list()?.sorted().orEmpty()

    @Test
    fun setIsPlacedVerifiedAndOnlyOnce() {
        val root = root()
        val first = assertIs<Outcome.Success<InstalledGeodata>>(GeodataInstaller(assets(), root).install()).value
        assertTrue(first.installedNow)
        assertEquals(root, first.dir.parentFile)
        for ((name, bytes) in files) assertContentEquals(bytes, File(first.dir, name).readBytes(), name)
        assertEquals(listOf(first.dir.name), names(root), "кроме набора — ничего: временный каталог переименован")
        assertEquals("dlc 0123456789ab, DB-IP 2026-01", first.manifest.summary)
        assertEquals(setOf("aa", "private"), first.manifest.geoIp)

        val again = assertIs<Outcome.Success<InstalledGeodata>>(GeodataInstaller(assets(), root).install()).value
        assertFalse(again.installedNow, "тот же набор не переносится заново")
        assertEquals(first.dir, again.dir)
    }

    @Test
    fun fileThatDiffersFromManifestIsNotInstalled() {
        val root = root()
        val tampered = files + ("geosite.dat" to "другие байты".toByteArray())
        val r = assertIs<Outcome.Failure>(GeodataInstaller(assets(set = tampered), root).install())
        assertEquals(DiagCode.GEODATA_UNAVAILABLE, r.errors.single().code)
        assertTrue("geosite.dat" in r.errors.single().message, r.errors.single().message)
        assertEquals(emptyList(), names(root), "ни набора, ни временного каталога")
    }

    @Test
    fun interruptedCopyLeavesNoSetAndNextStartFinishesIt() {
        val root = root()
        val r = assertIs<Outcome.Failure>(GeodataInstaller(assets(broken = "geodata/geoip.dat"), root).install())
        assertEquals(DiagCode.GEODATA_UNAVAILABLE, r.errors.single().code)
        assertTrue(names(root).all { it.startsWith(".") }, "после обрыва — только временный каталог: ${names(root)}")

        val ok = assertIs<Outcome.Success<InstalledGeodata>>(GeodataInstaller(assets(), root).install()).value
        assertTrue(ok.installedNow)
        assertEquals(listOf(ok.dir.name), names(root), "временный каталог прерванного переноса удалён")
    }

    @Test
    fun newSetReplacesOldAndForeignFilesStay() {
        val root = root()
        File(root, "not-a-set").mkdirs()
        val old = assertIs<Outcome.Success<InstalledGeodata>>(GeodataInstaller(assets(), root).install()).value
        val next = assertIs<Outcome.Success<InstalledGeodata>>(
            GeodataInstaller(assets(manifest = manifestJson(files, release = "2026-02")), root).install(),
        ).value
        assertTrue(next.dir != old.dir)
        assertFalse(old.dir.exists(), "прежний набор удалён")
        assertEquals(listOf(next.dir.name, "not-a-set").sorted(), names(root))
    }

    @Test
    fun missingSetIsExplicit() {
        val r = assertIs<Outcome.Failure>(GeodataInstaller(Assets(emptyMap()), root()).install())
        assertEquals(DiagCode.GEODATA_UNAVAILABLE, r.errors.single().code)
    }

    @Test
    fun manifestThatPointsOutsideTheSetIsRejected() {
        val cases = mapOf(
            "путь вверх" to manifestJson(files + ("../escape" to byteArrayOf(1))),
            "каталог в имени" to manifestJson(files + ("sub/file" to byteArrayOf(1))),
            "скрытый файл" to manifestJson(files + (".hidden" to byteArrayOf(1))),
            "оглавление в списке" to manifestJson(files + ("manifest.json" to byteArrayOf(1))),
            "нет geosite.dat" to manifestJson(files - "geosite.dat"),
            "чужой формат" to manifestJson(files).replace("dppass.geodata", "other"),
            "новая версия формата" to manifestJson(files).replace("\"format_version\": 2", "\"format_version\": 3"),
            // Версия 1: атрибуты списка вразбивку, без сочетаний.
            "прежняя версия формата" to manifestJson(files).replace("\"format_version\": 2", "\"format_version\": 1"),
            "атрибуты не сочетаниями" to manifestJson(files, geosite = JsonArray(listOf(JsonString("ads")))),
            "пустое сочетание" to manifestJson(files, geosite = attrSets(emptyList())),
            "повтор в сочетании" to manifestJson(files, geosite = attrSets(listOf("ads", "ads"))),
            "не JSON" to "{",
        )
        for ((name, text) in cases) {
            val r = GeodataManifest.parse(text)
            assertIs<Outcome.Failure>(r, name)
            assertEquals(DiagCode.GEODATA_UNAVAILABLE, r.errors.single().code, name)
        }
    }

    /** Договор со сборщиком: эталон его оглавления (tools/xray/geodata, TestManifestMatchesGolden). */
    @Test
    fun builderManifestParses() {
        val text = File(System.getProperty("dppass.repoRoot"), "tests/data/geodata/manifest.json").readText()
        val m = assertIs<Outcome.Success<GeodataManifest>>(GeodataManifest.parse(text)).value
        assertEquals("dlc 0123456789ab, DB-IP 2026-01", m.summary)
        assertEquals(setOf("geoip.dat", "geosite.dat", "NOTICE.txt"), m.files.map { it.name }.toSet())
        assertEquals(setOf("aa", "ab", "private"), m.geoIp)
        assertEquals(listOf(setOf("ads", "cn")), m.geoSite["example-b"])
        assertEquals(listOf(setOf("ads"), setOf("cn")), m.geoSite["example-split"])
        assertEquals(setOf("ads", "cn"), m.siteAttributes("example-split"))
        assertFalse(m.siteHasRuleWithAll("example-split", listOf("ads", "cn")), "@ads и @cn — у разных правил")
        assertTrue(m.siteHasRuleWithAll("example-b", listOf("cn", "ads")))
        assertTrue(m.siteHasRuleWithAll("example-b", emptyList()), "без атрибутов — весь список")
        assertFalse(m.siteHasRuleWithAll("example-d", emptyList()), "списка нет")
        assertEquals(setOf("example-a", "example-b", "example-all", "example-c", "example-split"), m.geoSite.keys)
    }
}
