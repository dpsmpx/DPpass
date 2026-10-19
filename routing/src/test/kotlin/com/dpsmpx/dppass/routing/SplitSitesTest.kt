package com.dpsmpx.dppass.routing

import com.dpsmpx.dppass.diagnostics.DiagCode
import com.dpsmpx.dppass.diagnostics.Outcome
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertTrue

class SplitSitesTest {
    private fun ok(text: String): SplitSites = assertIs<Outcome.Success<SplitSites>>(SplitSites.parse(text)).value

    @Test
    fun domainsAndGeositeListsInNormalForm() {
        val s = ok(
            """
            # мои сайты
            Example.COM.
            *.media.example.org

            .cdn.example.net
            geosite:EXAMPLE-A
            geosite:example-b@ads
            """.trimIndent(),
        )
        assertEquals(listOf("example.com", "media.example.org", "cdn.example.net"), s.domains)
        assertEquals(listOf("example-a", "example-b@ads"), s.geoSites)
        assertEquals(5, s.size)
    }

    @Test
    fun repeatsCountOnce() {
        val s = ok("example.com\nEXAMPLE.com\ngeosite:example-a\ngeosite:Example-A")
        assertEquals(listOf("example.com"), s.domains)
        assertEquals(listOf("example-a"), s.geoSites)
    }

    @Test
    fun emptyTextIsEmptyList() {
        assertTrue(ok("").isEmpty)
        assertTrue(ok("  \n# только комментарий\n").isEmpty)
        assertTrue(SplitSites.NONE.isEmpty)
    }

    @Test
    fun badLinesAreRejectedWithTheirNumbers() {
        // Молча выброшенная запись — сайт, который пойдёт не так, как задумано (D-05): весь список не принимается.
        val r = assertIs<Outcome.Failure>(SplitSites.parse("example.com\nhttps://example.org/path\ngeosite:\n1.2.3.4"))
        assertEquals(
            listOf(
                DiagCode.DOMAIN_INVALID to "settings.split_sites[2]",
                DiagCode.GEO_CODE_INVALID to "settings.split_sites[3]",
                DiagCode.DOMAIN_INVALID to "settings.split_sites[4]",
            ),
            r.errors.map { it.code to it.path },
        )
        assertTrue("строка 2" in r.errors.first().message)
    }

    @Test
    fun entriesAreLimited() {
        val many = (1..SplitSites.MAX_ENTRIES + 1).joinToString("\n") { "site$it.example.com" }
        val r = assertIs<Outcome.Failure>(SplitSites.parse(many))
        assertEquals(DiagCode.LIMIT_EXCEEDED, r.errors.single().code)
        ok((1..SplitSites.MAX_ENTRIES).joinToString("\n") { "site$it.example.com" })
    }

    @Test
    fun formatRoundTrips() {
        val s = ok("geosite:example-a\nexample.com")
        assertEquals("example.com\ngeosite:example-a", s.format())
        assertEquals(s, ok(s.format()))
    }

    @Test
    fun conditionsMatchSubdomainsAndLists() {
        val c = ok("example.com\ngeosite:example-a").conditions()
        assertEquals(listOf(DomainMatcher.Suffix("example.com")), c.domains)
        assertEquals(listOf("example-a"), c.geoSites)
        assertTrue(c.domains.single().matches("video.example.com"))
    }
}
