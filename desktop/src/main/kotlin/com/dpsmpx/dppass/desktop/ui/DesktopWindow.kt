package com.dpsmpx.dppass.desktop.ui

import com.dpsmpx.dppass.desktop.DesktopGraph
import com.dpsmpx.dppass.desktop.DesktopPrefs
import com.dpsmpx.dppass.desktop.DesktopSession
import com.dpsmpx.dppass.desktop.SessionStatus
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.launch
import java.awt.Dimension
import java.awt.event.KeyEvent
import java.io.File
import javax.swing.JFrame
import javax.swing.JMenu
import javax.swing.JMenuBar
import javax.swing.JMenuItem
import javax.swing.JOptionPane
import javax.swing.JRadioButtonMenuItem
import javax.swing.JTabbedPane
import javax.swing.KeyStroke
import javax.swing.WindowConstants

/**
 * Окно DPpass для Linux (D-74): «Подключение», «Серверы», «Подписки»,
 * «Журнал»; меню «Импорт» — буфер обмена и файл (D-42). Закрытие окна —
 * выход: ядро и правила маршрутизации убирает `DesktopSession.shutdownNow`.
 */
class DesktopWindow(private val graph: DesktopGraph, private val session: DesktopSession, private val scope: CoroutineScope) {
    private val prefs = DesktopPrefs(File(graph.paths.data, "settings.properties"))
    private val frame = JFrame("DPpass")

    fun show() {
        Theme.apply(prefs.theme, System.getenv(), System.getProperty("user.home"))
        lateinit var servers: ServersPanel
        lateinit var subscriptions: SubscriptionsPanel
        lateinit var connect: ConnectPanel
        val changed = {
            servers.refresh()
            connect.render(session.status.value)
        }
        subscriptions = SubscriptionsPanel(graph, scope, changed)
        val import = ImportFlow(graph, scope, { frame }, subscriptions, changed)
        connect = ConnectPanel(graph, session, prefs, import::fromClipboard)
        servers = ServersPanel(graph, prefs, scope) { session.status.value }
        val log = LogPanel(graph)
        val tabs = JTabbedPane().apply {
            addTab("Подключение", connect)
            addTab("Серверы", servers)
            addTab("Подписки", subscriptions)
            addTab("Журнал", log)
            addChangeListener {
                when (selectedComponent) {
                    servers -> servers.refresh()
                    subscriptions -> subscriptions.reload()
                    log -> log.reload()
                }
            }
        }
        frame.jMenuBar = menu(import)
        frame.contentPane = tabs
        frame.defaultCloseOperation = WindowConstants.EXIT_ON_CLOSE
        frame.minimumSize = Dimension(MIN_WIDTH, MIN_HEIGHT)
        frame.setSize(WIDTH, HEIGHT)
        frame.setLocationRelativeTo(null)
        subscriptions.reload()
        servers.refresh()
        scope.launch(Edt) {
            session.status.collect { s ->
                connect.render(s)
                servers.refresh()
                // Подключение или его отказ мог сменить «последний удачный» и паузы серверов (D-15).
                if (s is SessionStatus.Failed) log.reload()
            }
        }
        frame.isVisible = true
    }

    private fun menu(import: ImportFlow): JMenuBar = JMenuBar().apply {
        add(
            JMenu("Импорт").apply {
                add(item("Из буфера обмена", KeyEvent.VK_V) { import.fromClipboard() })
                add(item("Из файла…", KeyEvent.VK_O) { import.fromFile() })
            },
        )
        add(
            JMenu("Вид").apply {
                val current = prefs.theme
                for ((choice, title) in listOf(ThemeChoice.AUTO to "Тема системы", ThemeChoice.LIGHT to "Светлая", ThemeChoice.DARK to "Тёмная")) {
                    add(
                        JRadioButtonMenuItem(title, choice == current).apply {
                            addActionListener {
                                prefs.theme = choice
                                JOptionPane.showMessageDialog(frame, "Тема сменится при следующем запуске DPpass.", "Тема", JOptionPane.INFORMATION_MESSAGE)
                            }
                        },
                    )
                }
            },
        )
    }

    private fun item(title: String, key: Int, action: () -> Unit) = JMenuItem(title).apply {
        accelerator = KeyStroke.getKeyStroke(key, java.awt.event.InputEvent.CTRL_DOWN_MASK or java.awt.event.InputEvent.SHIFT_DOWN_MASK)
        addActionListener { action() }
    }

    private companion object {
        const val WIDTH = 720
        const val HEIGHT = 640
        const val MIN_WIDTH = 520
        const val MIN_HEIGHT = 480
    }
}
