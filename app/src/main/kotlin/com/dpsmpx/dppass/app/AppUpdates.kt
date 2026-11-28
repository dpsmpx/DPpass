package com.dpsmpx.dppass.app

import android.content.Intent
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.provider.Settings
import com.dpsmpx.dppass.R
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.json.JSONArray
import java.io.ByteArrayOutputStream
import java.io.File
import java.net.URI
import java.security.MessageDigest
import javax.net.ssl.HttpsURLConnection

/** UI-owned direct distribution updater. All network and archive work is off-main. */
internal class AppUpdates(private val activity: MainActivity) {
    private val prefs = activity.getSharedPreferences("app-updates", 0)
    private val pm = activity.packageManager
    private var awaitingPermission = false
    var available: ReleaseUpdate? = null
        private set
    var busy = false
        private set
    private var status = R.string.app_update_idle
    val statusText: String get() = if (status == R.string.app_update_available)
        activity.getString(status, available?.tag.orEmpty()) else activity.getString(status)
    val visibleUpdate: ReleaseUpdate? get() = available?.takeUnless { prefs.getLong("hidden", -1L) == it.code }

    private fun supported() = activity.packageName == "com.dpsmpx.dppass" &&
        Build.SUPPORTED_ABIS.contains("arm64-v8a")

    fun hide() {
        available?.let { prefs.edit().putLong("hidden", it.code).apply() }
        activity.changed()
    }

    fun check(manual: Boolean) {
        if (busy) return
        if (!supported()) {
            status = R.string.app_update_unsupported
            if (manual) activity.toast(statusText)
            return
        }
        busy = true
        status = R.string.app_update_checking
        activity.changed()
        activity.scope.launch {
            try {
                available = withContext(Dispatchers.IO) { latest(installedCode()) }
                if (manual) prefs.edit().remove("hidden").apply()
                status = if (available == null) R.string.app_update_current else R.string.app_update_available
                if (manual) activity.toast(statusText)
            } catch (e: CancellationException) {
                throw e
            } catch (_: Exception) {
                status = R.string.app_update_failed
                if (manual) activity.toast(statusText)
            } finally {
                busy = false
                activity.changed()
            }
        }
    }

    fun resumeAfterPermission() {
        if (!awaitingPermission) return
        awaitingPermission = false
        if (pm.canRequestPackageInstalls()) install()
    }

    fun install() {
        val update = available ?: return
        if (busy || !supported()) return
        if (!pm.canRequestPackageInstalls()) {
            awaitingPermission = true
            try {
                activity.toast(activity.getString(R.string.app_update_permission))
                activity.startActivity(Intent(Settings.ACTION_MANAGE_UNKNOWN_APP_SOURCES, Uri.parse("package:${activity.packageName}")))
            } catch (_: Exception) {
                awaitingPermission = false
                activity.toast(activity.getString(R.string.app_update_failed))
            }
            return
        }
        busy = true
        status = R.string.app_update_downloading
        activity.changed()
        activity.scope.launch {
            try {
                withContext(Dispatchers.IO) {
                    val job = currentCoroutineContext()
                    downloadAndVerify(update) { job.ensureActive() }
                }
                val uri = UpdateApkProvider.uri(activity.packageName)
                activity.startActivity(Intent(Intent.ACTION_VIEW).apply {
                    setDataAndType(uri, "application/vnd.android.package-archive")
                    addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
                })
                status = R.string.app_update_installer
            } catch (e: CancellationException) {
                throw e
            } catch (_: Exception) {
                status = R.string.app_update_failed
                activity.toast(statusText)
            } finally {
                busy = false
                activity.changed()
            }
        }
    }

    @Suppress("DEPRECATION")
    private fun installed(): PackageInfo = pm.getPackageInfo(activity.packageName,
        if (Build.VERSION.SDK_INT >= 28) PackageManager.GET_SIGNING_CERTIFICATES else PackageManager.GET_SIGNATURES)

    @Suppress("DEPRECATION")
    private fun code(info: PackageInfo): Long = if (Build.VERSION.SDK_INT >= 28) info.longVersionCode else info.versionCode.toLong()

    private fun installedCode() = code(installed())

    @Suppress("DEPRECATION")
    private fun signers(info: PackageInfo): Set<String> {
        val signatures = if (Build.VERSION.SDK_INT >= 28) info.signingInfo?.apkContentsSigners else info.signatures
        return signatures.orEmpty().map { sha256(it.toByteArray()) }.toSet()
    }

    private fun sha256(bytes: ByteArray): String = hex(MessageDigest.getInstance("SHA-256").digest(bytes))
    private fun hex(bytes: ByteArray): String = bytes.joinToString("") { "%02x".format(it.toInt() and 255) }

    private fun latest(installed: Long): ReleaseUpdate? {
        val data = request("https://api.github.com/repos/dpsmpx/DPpass/releases?per_page=100", api = true) { connection ->
            val out = ByteArrayOutputStream()
            connection.inputStream.use { input ->
                val buffer = ByteArray(8192)
                while (true) {
                    val n = input.read(buffer)
                    if (n < 0) break
                    require(out.size() + n <= 8 * 1024 * 1024)
                    out.write(buffer, 0, n)
                }
            }
            out.toString("UTF-8")
        }
        val releases = JSONArray(data)
        val candidates = mutableListOf<ReleaseUpdate>()
        for (i in 0 until releases.length()) {
            val release = releases.getJSONObject(i)
            if (release.optBoolean("draft", true)) continue
            val assets = release.optJSONArray("assets") ?: continue
            for (j in 0 until assets.length()) {
                val asset = assets.getJSONObject(j)
                if (asset.optString("state") != "uploaded") continue
                ReleaseUpdatePolicy.candidate(release.optString("tag_name"), asset.optString("name"),
                    asset.optLong("size", -1L), asset.optString("browser_download_url"), installed)?.let(candidates::add)
            }
        }
        return ReleaseUpdatePolicy.best(candidates)
    }

    @Suppress("DEPRECATION")
    private fun downloadAndVerify(update: ReleaseUpdate, checkActive: () -> Unit) {
        val target = UpdateApkProvider.file(activity)
        require(target.parentFile?.let { it.isDirectory || it.mkdirs() } == true)
        val temp = File.createTempFile("download-", ".apk", target.parentFile)
        try {
            val digest = MessageDigest.getInstance("SHA-256")
            request(update.url, api = false) { connection ->
                var total = 0L
                connection.inputStream.use { input ->
                    temp.outputStream().use { output ->
                        val buffer = ByteArray(64 * 1024)
                        while (true) {
                            checkActive()
                            val n = input.read(buffer)
                            if (n < 0) break
                            total += n
                            require(total <= update.size)
                            digest.update(buffer, 0, n)
                            output.write(buffer, 0, n)
                        }
                    }
                }
                require(total == update.size && hex(digest.digest()) == update.sha256)
            }
            checkActive()
            val candidate = pm.getPackageArchiveInfo(temp.absolutePath,
                if (Build.VERSION.SDK_INT >= 28) PackageManager.GET_SIGNING_CERTIFICATES else PackageManager.GET_SIGNATURES)
                ?: error("invalid APK")
            val current = installed()
            require(candidate.packageName == activity.packageName && code(candidate) == update.code && code(candidate) > code(current))
            val signer = signers(candidate)
            require(signer.isNotEmpty() && signer == signers(current))
            checkActive()
            require(temp.renameTo(target))
        } finally {
            temp.delete()
        }
    }

    /** Explicit HTTPS-only redirect allowlist; no credentials, cookies or subscription metadata. */
    private fun <T> request(initial: String, api: Boolean, block: (HttpsURLConnection) -> T): T {
        var url = URI(initial)
        repeat(5) {
            require(url.scheme == "https" && url.userInfo == null && url.port in listOf(-1, 443))
            require(url.host in if (api) setOf("api.github.com") else setOf("github.com", "release-assets.githubusercontent.com", "objects.githubusercontent.com"))
            val c = url.toURL().openConnection() as HttpsURLConnection
            try {
                c.instanceFollowRedirects = false
                c.connectTimeout = 15_000
                c.readTimeout = 30_000
                c.setRequestProperty("User-Agent", "DPpass-Update")
                c.setRequestProperty("Accept", if (api) "application/vnd.github+json" else "application/octet-stream")
                val status = c.responseCode
                if (status in listOf(301, 302, 303, 307, 308)) {
                    url = url.resolve(c.getHeaderField("Location") ?: error("missing redirect"))
                } else {
                    require(status == 200)
                    return block(c)
                }
            } finally {
                c.disconnect()
            }
        }
        error("too many redirects")
    }
}
