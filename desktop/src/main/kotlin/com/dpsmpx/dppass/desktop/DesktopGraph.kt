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
import com.dpsmpx.dppass.network.SystemProbeNetwork
import com.dpsmpx.dppass.storage.EncryptingBlobStore
import com.dpsmpx.dppass.storage.FileBlobStore
import com.dpsmpx.dppass.storage.KeyWrapper
import com.dpsmpx.dppass.storage.StorageReset
import com.dpsmpx.dppass.storage.WrappedKeyProvider
import com.dpsmpx.dppass.subscriptions.HttpsSubscriptionFetcher
import com.dpsmpx.dppass.subscriptions.SubscriptionFetcher
import com.dpsmpx.dppass.tunnel.PlatformTraits
import java.io.File

/**
 * Сборка зависимостей оболочки ПК (D-74, D-97) — как `AppGraph` на Android:
 * ядро DPpass, ядро Xray в процессе (D-25, библиотека пакета), набор
 * геоданных (D-27), хранилище в каталоге данных (D-19), подписки по HTTPS
 * (D-36). Чем Linux и Windows различаются — права на туннель, туннель, ключ
 * данных, пробы мимо туннеля — собирает [Parts]. Отказ части — диагностика
 * в журнале и причина у вызова, а не падение окна.
 */
class DesktopGraph(
    val core: DPpassCore,
    val engine: XrayProxyEngine,
    /** Мост ядра — для остановки при выходе без корутин (`Runtime.addShutdownHook`). */
    val runtime: XrayRuntime?,
    /** Система ПК (D-74, D-97): можно ли поднять туннель, какая сеть. */
    val host: DesktopHost,
    val tunnels: DesktopTunnels,
    val fetcher: SubscriptionFetcher,
    val log: MemoryLogSink,
    val logger: Logger,
    val paths: DesktopPaths,
    /** Проверка сети (D-79): пробы мимо туннеля, память режима (D-64). */
    val networkCheck: DesktopNetworkCheck,
    /** Поиск устройства раздачи и сопряжение (D-85, D-102): сокеты мимо туннеля, как у проб; null — без библиотеки моста на Windows. */
    val relayNetworks: RelayNetworks?,
    /** Точка доступа ПК для раздачи (D-84, D-101); null — без библиотеки моста на Windows её не узнать. */
    val shares: DesktopShares?,
    /** Что не поднялось при сборке: показывается в окне. */
    val problems: List<Diagnostic>,
) {
    /** Чем сборка различается по системе (D-74, D-97). */
    private class Parts(
        val host: DesktopHost,
        val tunnels: DesktopTunnels,
        val keyWrapper: KeyWrapper,
        val traits: PlatformTraits,
        val probeNetwork: DesktopProbeNetwork,
        val relayNetworks: RelayNetworks?,
        val shares: DesktopShares?,
    )

    companion object {
        /** Имя «пакета» оболочки: у TunnelSpec собственный пакет всегда вне туннеля (D-17). */
        const val SELF: String = "com.dpsmpx.dppass"

        /** Версия оболочки — в `User-Agent` подписки (D-33): из манифеста jar. */
        val VERSION: String = DesktopGraph::class.java.`package`?.implementationVersion ?: "dev"

        /**
         * Первая строка «Журнала» и его копии (D-87): версия оболочки, Java и
         * архитектура — без имени ПК, пользователя и прочих идентификаторов (D-12).
         */
        fun sessionLine(): String = "session_start version=$VERSION java=${Runtime.version().feature()} arch=${System.getProperty("os.arch")}"

        fun build(paths: DesktopPaths): DesktopGraph {
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
            val runtime = JniXrayRuntime.load({ loadLibrary(paths) }, assetDir.path)
            when (runtime) {
                is Outcome.Success -> logger.info("engine_loaded", "backend" to Safe(XrayBackend.ID), "version" to Safe(runtime.value.version()))
                is Outcome.Failure -> report(runtime)
            }
            val loaded = runtime is Outcome.Success
            val parts = if (paths.windows) windows(loaded, logger) else linux(SystemLinuxPlatform(), loaded, logger)
            // Ключ данных — в своём каталоге (D-19); поверх существующих записей новый не создаётся.
            val keys = WrappedKeyProvider(FileBlobStore(paths.keys), parts.keyWrapper, dataPresent = { StorageReset.hasData(data) })
            val engine = XrayProxyEngine(runtime)
            val core = DPpassCore(
                // На ПК ядро перехватывает DNS на порт 53 любого адреса (D-74, D-97).
                compiler = XrayCompiler(geodata = geoCodes, dnsHijackAnyAddress = true),
                engine = engine,
                store = EncryptingBlobStore(data, keys),
                clock = Clock.SYSTEM,
                selfPackage = SELF,
                platform = parts.traits,
                storageRecovery = StorageReset(data, keys, Clock.SYSTEM),
                logSink = sink,
                engineDetails = listOf("geodata" to geodataSummary, "platform" to parts.host.id),
            )
            core.restore().filter { it.isError }.forEach { problems += it }
            return DesktopGraph(
                core = core,
                engine = engine,
                runtime = runtime.valueOrNull(),
                host = parts.host,
                tunnels = parts.tunnels,
                fetcher = HttpsSubscriptionFetcher(Clock.SYSTEM),
                log = sink,
                logger = logger,
                paths = paths,
                networkCheck = DesktopNetworkCheck(core.log, parts.probeNetwork, parts.host::network),
                relayNetworks = parts.relayNetworks,
                shares = parts.shares,
                problems = problems,
            )
        }

        /** Linux (D-74): `CAP_NET_ADMIN`, TUN с fd и правилами `ip`, метка сокетов мимо туннеля. */
        private fun linux(platform: LinuxPlatform, loaded: Boolean, logger: Logger): Parts {
            // Имена серверов — резолвером Go с меткой, мимо туннеля (D-29, D-74); без права метки
            // не ставятся, а подключение и так откажет с причиной.
            val marks = loaded && platform.hasNetAdmin()
            if (marks) LinuxNative.nativeMarkResolver(LinuxRoutes.MARK)
            // Пробы проверки сети — мимо туннеля (D-79): метка, как у сокетов ядра, и резолвер моста с меткой.
            val probeNetwork = LinuxProbeNetwork(
                mark = if (marks) { fd -> LinuxNative.nativeMarkSocket(fd, LinuxRoutes.MARK) } else null,
                resolver = if (loaded) {
                    { host ->
                        LinuxProbeNetwork.parseResolve(
                            host,
                            LinuxNative.nativeResolve(host.toByteArray(Charsets.UTF_8), LinuxProbeNetwork.RESOLVE_TIMEOUT_MILLIS),
                        )
                    }
                } else {
                    // Ядра нет — туннеля тоже: резолвер системы и так мимо него.
                    SystemProbeNetwork::resolve
                },
            )
            return Parts(
                host = LinuxHost(platform),
                tunnels = LinuxTunnels(LinuxTunnelProvider(platform, SELF, logger)),
                keyWrapper = PlainKeyWrapper(),
                traits = PlatformTraits(supportsExcludeRoute = true),
                probeNetwork = probeNetwork,
                relayNetworks = LinuxRelayNetworks.create(probeNetwork::tcpSocket),
                shares = LinuxShareInterfaces(),
            )
        }

        /**
         * Windows (D-97): права администратора, адаптер Wintun создаёт ядро,
         * ключ данных — под DPAPI. Без библиотеки моста функций Windows нет:
         * прав «нет», ключ данных недоступен с причиной, а не падение окна.
         */
        private fun windows(loaded: Boolean, logger: Logger): Parts {
            val elevated: () -> Boolean = if (loaded) WindowsNative::nativeElevated else { { false } }
            val alias = WINDOWS_TUN_ALIAS.toByteArray(Charsets.UTF_8)
            val host = WindowsHost(
                if (loaded) { { WindowsNative.nativeDefaultRoute(alias) } } else null,
                elevated,
                if (loaded) WindowsNative::nativeSystemTheme else { { -1 } },
            )
            return Parts(
                host = host,
                tunnels = WindowsTunnels(SELF, logger, elevated),
                keyWrapper = if (loaded) DpapiKeyWrapper() else DpapiKeyWrapper(NO_BRIDGE, NO_BRIDGE),
                traits = WindowsHost.TRAITS,
                probeNetwork = if (loaded) {
                    WindowsProbeNetwork(
                        host::tunnelUp,
                        { WindowsNative.nativeProbeInterface(alias) },
                        WindowsNative::nativeBindSocket,
                    ) { host, servers, index ->
                        WindowsNative.nativeResolveVia(
                            host.toByteArray(Charsets.UTF_8),
                            servers.joinToString("\n").toByteArray(Charsets.UTF_8),
                            index,
                            LinuxProbeNetwork.RESOLVE_TIMEOUT_MILLIS,
                        )
                    }
                } else {
                    WindowsProbeNetwork(host::tunnelUp)
                },
                relayNetworks = if (loaded) {
                    WindowsRelayNetworks.create({ WindowsNative.nativeRelayNetworks(alias) }, host::tunnelUp, WindowsNative::nativeBindSocket)
                } else {
                    null
                },
                shares = if (loaded) WindowsShareInterfaces { WindowsNative.nativeSharedInterfaces(alias) } else null,
            )
        }

        private val NO_BRIDGE: (ByteArray) -> ByteArray = { error("библиотека ядра не загружена — DPAPI недоступен, ключ данных не открыть") }

        /** Библиотека ядра и функций системы — из пакета, по абсолютному пути (не из `java.library.path`). */
        fun loadLibrary(paths: DesktopPaths) = System.load(paths.library.path)

        private const val LOG_CAPACITY = 2000
    }
}
