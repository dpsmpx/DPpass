package com.dpsmpx.dppass.desktop

import com.dpsmpx.dppass.core.Json
import com.dpsmpx.dppass.core.JsonNull
import com.dpsmpx.dppass.core.JsonString
import com.dpsmpx.dppass.core.JsonValue
import java.io.File
import java.nio.channels.DatagramChannel

/**
 * Самопроверка комплекта Windows (D-97) для `tools/desktop/windows_package.py`
 * в Wine: на рантайме комплекта собирается граф оболочки Windows — DLL моста,
 * набор геоданных, хранилище, — и ключ проходит DPAPI туда и обратно. Окна и
 * туннеля нет. Данные — в [data], а не в `%LOCALAPPDATA%`: проверка не
 * трогает данные пользователя. Отчёт — JSON в [out]; true — ядро загружено,
 * сборка без отказов, DPAPI вернул тот же ключ, сокет канала пробы виден
 * (флаг запуска для проб мимо туннеля, D-99), поиск точки доступа (ICS,
 * D-101) ответил через мост — в Wine её объектов нет, и ответ — отказ, но
 * не падение; сети ПК для устройства раздачи (D-102) разобраны.
 */
object WindowsSelfCheck {
    fun run(install: File, data: File, out: File): Boolean {
        val graph = DesktopGraph.build(DesktopPaths(data, install, windows = true))
        val version = graph.runtime?.version()
        // Без библиотеки моста функций DPAPI нет: и проверять нечего.
        val dpapi = version != null && try {
            val key = ByteArray(KEY_BYTES) { it.toByte() }
            val wrapper = DpapiKeyWrapper()
            wrapper.unwrap(wrapper.wrap(key)).contentEquals(key)
        } catch (e: Exception) {
            false
        }
        // Сокет канала JDK — тот, что проба привязывает к интерфейсу мимо туннеля (D-99).
        val probeSocket = DatagramChannel.open().use { LinuxProbeNetwork.fdOf(it) != null }
        // Поиск точки доступа через мост (D-101): что-то ответил — путь JNI и COM цел.
        val share = graph.shares?.find()?.seen
        // Сети ПК для устройства раздачи (D-102): ответ моста разобран — сколько интерфейсов.
        val relayNets = version?.let {
            WindowsRelayNetworks.parse(WindowsNative.nativeRelayNetworks(WINDOWS_TUN_ALIAS.toByteArray(Charsets.UTF_8)))?.size
        }
        val ok = version != null && graph.problems.isEmpty() && dpapi && probeSocket &&
            share?.startsWith("ics=") == true && relayNets != null
        val report = linkedMapOf<String, JsonValue>(
            "host" to JsonString(graph.host.id),
            "engine" to (Json.str(version) ?: JsonNull),
            "problems" to Json.strings(graph.problems.flatMap { it.renderWithCauses() }),
            "dpapi" to Json.bool(dpapi),
            "probe_socket" to Json.bool(probeSocket),
            "share" to (Json.str(share) ?: JsonNull),
            "relay_networks" to (relayNets?.let { Json.num(it) } ?: JsonNull),
            "tunnel_allowed" to Json.bool(graph.host.tunnelAllowed()),
            "log" to Json.strings(graph.log.snapshot().map { it.render() }),
        )
        out.writeText(Json.write(Json.obj(*report.toList().toTypedArray())) + "\n")
        return ok
    }

    private const val KEY_BYTES = 32
}
