package com.dpsmpx.dppass.desktop.ui

import com.dpsmpx.dppass.desktop.DesktopGraph
import com.dpsmpx.dppass.desktop.DesktopPrefs
import com.dpsmpx.dppass.desktop.DesktopSession
import com.dpsmpx.dppass.desktop.SessionStatus
import com.dpsmpx.dppass.desktop.SubscriptionAutoUpdate
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.launch
import java.awt.Dimension
import java.awt.event.KeyEvent
import javax.swing.JCheckBoxMenuItem
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
 * «Сеть» (проверка сети, D-79), «Журнал». Меню «Импорт» — буфер обмена и
 * файл (D-42); «Подключение» — автопереключение сервера (D-78) и проверка
 * сети при её смене (D-80). Пока окно открыто, применённая подписка
 * обновляется по сроку (D-77). Закрытие окна — выход: ядро и правила
 * маршрутизации убирает `DesktopSession.shutdownNow`.
 */
class DesktopWindow(
    private val graph: DesktopGraph,
    private val session: DesktopSession,
    private val prefs: DesktopPrefs,
    private val scope: CoroutineScope,
) {
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
        val network = NetworkPanel(graph.networkCheck, scope)
        val tabs = JTabbedPane().apply {
            // Без своего фона за ярлыками вкладок видна светлая подложка окна.
            isOpaque = true
            background = Theme.palette.bg
            addTab("Подключение", connect)
            addTab("Серверы", servers)
            addTab("Подписки", subscriptions)
            addTab("Сеть", network)
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
        SubscriptionAutoUpdate(
            graph.core,
            graph.fetcher,
            DesktopGraph.VERSION,
            session::connectedProfile,
            { session.reconnect(prefs.selectedServer) },
        ) {
            scope.launch(Edt) {
                subscriptions.reload()
                changed()
            }
        }.start(scope)
        scope.launch(Edt) { session.notice.collect(connect::renderNotice) }
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
            JMenu("Подключение").apply {
                // Согласие заранее заменять выбранный сервер, когда он перестал отвечать (D-58, D-78).
                add(
                    JCheckBoxMenuItem("Автопереключение сервера", prefs.autoSwitch).apply {
                        toolTipText = "Если выбранный сервер перестал отвечать, перейти на лучший другой без вопроса"
                        addActionListener {
                            prefs.autoSwitch = isSelected
                            graph.core.log.info("auto_switch", "on" to isSelected)
                        }
                    },
                )
                // Проверка новой сети при поднятом туннеле (D-80): выключено — только по кнопке на «Сети».
                add(
                    JCheckBoxMenuItem("Проверять сеть при её смене", prefs.checkOnNetworkChange).apply {
                        toolTipText = "Через 20 с после смены сети — та же проверка, что на вкладке «Сеть», не больше 4 раз в час; " +
                            "ориентиры видят адрес ПК в новой сети"
                        addActionListener {
                            prefs.checkOnNetworkChange = isSelected
                            graph.core.log.info("check_on_network_change", "on" to isSelected)
                        }
                    },
                )
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
