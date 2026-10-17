package com.dpsmpx.dppass.connection

import com.dpsmpx.dppass.diagnostics.DiagCode
import java.io.File
import java.util.Base64
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

/** Распознавание принесённого текста (D-42): только говорит, что это. */
class ImportClassifierTest {
    private fun doc(name: String) = File(System.getProperty("dppass.repoRoot"), "tests/data/$name").readText()

    @Test
    fun documentAddressLinksBase64AndGarbage() {
        assertEquals(ImportKind.Empty, ImportClassifier.classify(" \n "))
        assertEquals(ImportKind.OwnDocument, ImportClassifier.classify(doc("configs/valid-minimal.json")))
        assertEquals(
            ImportKind.SubscriptionUrl("https://sub.example.com/api/sub/t0ken"),
            ImportClassifier.classify("  https://sub.example.com/api/sub/t0ken\n"),
        )

        // Файл корпуса — список в base64, как его отдаёт панель.
        val b64 = doc("subscriptions/remnawave-links.txt")
        val links = String(Base64.getMimeDecoder().decode(b64.trim()))
        val plain = assertIs<ImportKind.Links>(ImportClassifier.classify(links))
        assertEquals(9 to 10, plain.usable to plain.total)
        assertTrue(plain.problems.isNotEmpty())
        val encoded = assertIs<ImportKind.Links>(ImportClassifier.classify(b64))
        assertEquals(plain.usable to plain.total, encoded.usable to encoded.total)

        assertIs<ImportKind.Unrecognized>(ImportClassifier.classify("просто текст"))
        assertIs<ImportKind.Unrecognized>(ImportClassifier.classify("""{"outbounds": []}"""))
        assertIs<ImportKind.Unrecognized>(ImportClassifier.classify("http://sub.example.com/x"))
        // Адрес с текстом вокруг — не адрес подписки.
        assertIs<ImportKind.Unrecognized>(ImportClassifier.classify("https://sub.example.com/x\nи ещё строка"))
    }

    @Test
    fun plainHttpAndOversizedTextAreRefusedWithReason() {
        val http = assertIs<ImportKind.Unrecognized>(ImportClassifier.classify("http://sub.example.com/x"))
        assertEquals(DiagCode.SUBSCRIPTION_FETCH_FAILED, http.reason?.code)
        // Строка https:// с управляющим символом — не адрес подписки, и причина — правило адреса,
        // а не «схема https:// неизвестна» из разбора ссылок.
        val control = assertIs<ImportKind.Unrecognized>(ImportClassifier.classify("https://sub.example.com/s\u0001"))
        assertEquals(DiagCode.SUBSCRIPTION_FETCH_FAILED, control.reason?.code)
        assertTrue("управляющих" in control.reason!!.message, control.reason.message)

        // Предел — до разбора: огромный текст не декодируется (T6).
        val huge = "vless://" + "a".repeat(ImportClassifier.MAX_BYTES)
        val big = assertIs<ImportKind.Unrecognized>(ImportClassifier.classify(huge))
        assertEquals(DiagCode.DOCUMENT_TOO_LARGE, big.reason?.code)
        // Ровно на пределе — не отказ по размеру: текст идёт в разбор.
        val edge = ImportClassifier.classify("x".repeat(ImportClassifier.MAX_BYTES))
        assertNotEquals(DiagCode.DOCUMENT_TOO_LARGE, (edge as? ImportKind.Unrecognized)?.reason?.code)
    }
}
