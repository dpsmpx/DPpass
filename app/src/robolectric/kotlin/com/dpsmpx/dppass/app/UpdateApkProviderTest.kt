package com.dpsmpx.dppass.app

import android.net.Uri
import android.os.ParcelFileDescriptor
import com.dpsmpx.dppass.app.UpdateApkProvider.Companion.MIME_TYPE
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.Robolectric
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.annotation.Config
import java.io.FileNotFoundException
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNull

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [26, 29, 36])
class UpdateApkProviderTest {
    @Test fun eachGrantUriResolvesToItsOwnReadOnlyFile() {
        val app = RuntimeEnvironment.getApplication()
        val first = "a".repeat(64)
        val second = "b".repeat(64)
        fun save(digest: String, text: String) = UpdateApkProvider.file(app, digest).apply {
            parentFile?.mkdirs()
            writeText(text)
        }
        val firstFile = save(first, "first")
        val secondFile = save(second, "second")
        val firstUri = UpdateApkProvider.uri(app.packageName, first)
        val secondUri = UpdateApkProvider.uri(app.packageName, second)
        val provider = Robolectric.setupContentProvider(UpdateApkProvider::class.java, "${app.packageName}.updates")

        try {
            fun read(uri: Uri): String = ParcelFileDescriptor.AutoCloseInputStream(provider.openFile(uri, "r"))
                .bufferedReader().use { it.readText() }
            assertEquals("first", read(firstUri))
            assertEquals("second", read(secondUri))
            assertEquals(MIME_TYPE, provider.getType(firstUri))
            assertFailsWith<FileNotFoundException> { provider.openFile(firstUri, "w") }
            val invalidUri = firstUri.buildUpon().appendQueryParameter("file", "different").build()
            assertNull(provider.getType(invalidUri))
            assertFailsWith<FileNotFoundException> { provider.openFile(invalidUri, "r") }
            val invalidPath = Uri.parse("content://${app.packageName}.updates/elsewhere/$first.apk")
            assertFailsWith<FileNotFoundException> { provider.openFile(invalidPath, "r") }
        } finally {
            firstFile.delete()
            secondFile.delete()
        }
    }
}
