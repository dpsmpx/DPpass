package com.dpsmpx.dppass.desktop

import com.dpsmpx.dppass.desktop.ui.DesktopWindow
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.future.future
import java.io.File
import javax.swing.SwingUtilities
import kotlin.system.exitProcess

/**
 * Оболочка Linux (D-74). Без аргументов — окно; `--self-check FILE` —
 * проверка туннеля на настоящем ядре для `tools/desktop/netns_check.py`
 * (отчёт — в FILE, код выхода 0 — туннель поднялся и закрылся).
 */
fun main(args: Array<String>) {
    val install = DesktopPaths.installDir(File(DesktopGraph::class.java.protectionDomain.codeSource.location.toURI()))
    if (args.size == 2 && args[0] == "--self-check") {
        val ok = CoroutineScope(Dispatchers.Default).future { SelfCheck.run(install, File(args[1])) }.get()
        exitProcess(if (ok) 0 else 1)
    }
    val home = System.getProperty("user.home")
    val paths = DesktopPaths(DesktopPaths.dataDir(System.getenv(), home), install)
    val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
    val graph = DesktopGraph.build(paths)
    val session = DesktopSession(graph, scope)
    // Выход — ядро и правила маршрутизации убираются и при закрытии окна, и по сигналу.
    Runtime.getRuntime().addShutdownHook(Thread(session::shutdownNow, "dppass-shutdown"))
    SwingUtilities.invokeLater { DesktopWindow(graph, session, scope).show() }
}
