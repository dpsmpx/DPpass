package com.dpsmpx.dppass.desktop

import com.dpsmpx.dppass.connection.DPpassCore
import com.dpsmpx.dppass.core.Clock
import com.dpsmpx.dppass.diagnostics.Diagnostic
import com.dpsmpx.dppass.diagnostics.Logger
import com.dpsmpx.dppass.diagnostics.MemoryLogSink
import com.dpsmpx.dppass.diagnostics.Outcome
import com.dpsmpx.dppass.diagnostics.Safe
import com.dpsmpx.dppass.engine.xray.GeodataCodes
import com.dpsmpx.dppass.engine.xray.GeodataInstaller
import com.dpsmpx.dppass.engine.xray.JniXrayRuntime
import com.dpsmpx.dppass.engine.xray.XrayBackend
import com.dpsmpx.dppass.engine.xray.XrayCompiler
import com.dpsmpx.dppass.engine.xray.XrayProxyEngine
import com.dpsmpx.dppass.engine.xray.XrayRuntime
import com.dpsmpx.dppass.storage.EncryptingBlobStore
import com.dpsmpx.dppass.storage.FileBlobStore
import com.dpsmpx.dppass.storage.StorageReset
import com.dpsmpx.dppass.storage.WrappedKeyProvider
import com.dpsmpx.dppass.subscriptions.HttpsSubscriptionFetcher
import com.dpsmpx.dppass.subscriptions.SubscriptionFetcher
import com.dpsmpx.dppass.tunnel.PlatformTraits
import java.io.File

/**
 * Сборка зависимостей оболочки Linux (D-74) — как `AppGraph` на Android:
 * ядро DPpass, ядро Xray в процессе (D-25, библиотека пакета), набор
 * геоданных (D-27), хранилище в `$XDG_DATA_HOME/dppass` (D-19), подписки по
 * HTTPS (D-36), туннель Linux. Отказ части — диагностика в журнале и
 * причина у вызова, а не падение окна.
 */
class DesktopGraph(
    val core: DPpassCore,
    val engine: XrayProxyEngine,
    /** Мост ядра — для остановки при выходе без корутин (`Runtime.addShutdownHook`). */
    val runtime: XrayRuntime?,
    val tunnels: LinuxTunnelProvider,
    val platform: LinuxPlatform,
    val fetcher: SubscriptionFetcher,
    val log: MemoryLogSink,
    val logger: Logger,
    val paths: DesktopPaths,
    /** Что не поднялось при сборке: показывается в окне. */
    val problems: List<Diagnostic>,
) {
    companion object {
        /** Имя «пакета» оболочки: у TunnelSpec собственный пакет всегда вне туннеля (D-17). */
        const val SELF: String = "com.dpsmpx.dppass"

        /** Версия оболочки — в `User-Agent` подписки (D-33): из манифеста jar. */
        val VERSION: String = DesktopGraph::class.java.`package`?.implementationVersion ?: "dev"

        fun build(paths: DesktopPaths, platform: LinuxPlatform = SystemLinuxPlatform()): DesktopGraph {
            val sink = MemoryLogSink(LOG_CAPACITY)
            val logger = Logger("desktop", sink, Clock.SYSTEM::nowMillis)
            val problems = mutableListOf<Diagnostic>()
            fun report(r: Outcome<*>) {
                if (r is Outcome.Failure) {
                    r.errors.forEach(logger::diagnostic)
                    problems += r.errors
                }
            }
            report(paths.prepare())
            val data = FileBlobStore(paths.state)
            // Ключ данных — в своём каталоге (D-19); поверх существующих записей новый не создаётся.
            val keys = WrappedKeyProvider(FileBlobStore(paths.keys), PlainKeyWrapper(), dataPresent = { StorageReset.hasData(data) })
            val (assetDir, geoCodes, geodataSummary) = when (val g = GeodataInstaller({ File(paths.install, it).inputStream() }, paths.geodata).install()) {
                is Outcome.Success -> {
                    logger.info("geodata_ready", "set" to Safe(g.value.manifest.summary), "installed_now" to g.value.installedNow)
                    Triple(g.value.dir, GeodataCodes.Installed(g.value.manifest), g.value.manifest.summary)
                }
                is Outcome.Failure -> {
                    report(g)
                    Triple(paths.geodata, GeodataCodes.Missing(g.errors.first().message), "none")
                }
            }
            val runtime = JniXrayRuntime.load({ System.load(paths.library.path) }, assetDir.path)
            when (runtime) {
                is Outcome.Success -> {
                    logger.info("engine_loaded", "backend" to Safe(XrayBackend.ID), "version" to Safe(runtime.value.version()))
                    // Имена серверов — резолвером Go с меткой, мимо туннеля (D-29, D-74); без права метки
                    // не ставятся, а подключение и так откажет с причиной.
                    if (platform.hasNetAdmin()) LinuxNative.nativeMarkResolver(LinuxRoutes.MARK)
                }
                is Outcome.Failure -> report(runtime)
            }
            val engine = XrayProxyEngine(runtime)
            val core = DPpassCore(
                // На Linux ядро перехватывает DNS на порт 53 любого адреса (D-74).
                compiler = XrayCompiler(geodata = geoCodes, dnsHijackAnyAddress = true),
                engine = engine,
                store = EncryptingBlobStore(data, keys),
                clock = Clock.SYSTEM,
                selfPackage = SELF,
                platform = PlatformTraits(supportsExcludeRoute = true),
                storageRecovery = StorageReset(data, keys, Clock.SYSTEM),
                logSink = sink,
                engineDetails = listOf("geodata" to geodataSummary, "platform" to "linux"),
            )
            core.restore().filter { it.isError }.forEach { problems += it }
            return DesktopGraph(
                core = core,
                engine = engine,
                runtime = runtime.valueOrNull(),
                tunnels = LinuxTunnelProvider(platform, SELF, logger),
                platform = platform,
                fetcher = HttpsSubscriptionFetcher(Clock.SYSTEM),
                log = sink,
                logger = logger,
                paths = paths,
                problems = problems,
            )
        }

        private const val LOG_CAPACITY = 2000
    }
}
