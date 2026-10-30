package com.dpsmpx.dppass.desktop.ui

import com.dpsmpx.dppass.connection.ServerlessSettings
import com.dpsmpx.dppass.desktop.DesktopGraph
import com.dpsmpx.dppass.desktop.DesktopPrefs
import com.dpsmpx.dppass.desktop.DesktopSession
import com.dpsmpx.dppass.desktop.SessionStatus
import com.dpsmpx.dppass.desktop.SubscriptionAutoUpdate
import com.dpsmpx.dppass.diagnostics.Safe
import com.dpsmpx.dppass.engine.ServerlessPlan
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.launch
import java.awt.Dimension
import java.awt.event.KeyEvent
import javax.swing.ButtonGroup
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
 * Окно DPpass для ПК (D-74, D-97): «Подключение», «Серверы», «Подписки»,
 * «Сеть» (проверка сети, D-79), «Раздача» (точка доступа ПК, D-84),
 * «Устройства раздачи» (подключение через телефон, D-85), «Журнал»; на
 * Windows раздачи и устройств раздачи нет — и вкладок тоже. Меню «Импорт» — буфер обмена и
 * файл (D-42); «Подключение» — автопереключение сервера (D-78), разбиение
 * ClientHello к серверу (D-81), сайты напрямую с разбиением (D-82) и
 * проверка сети при её смене (D-80). Пока окно открыто, применённая подписка
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

    /** Перерисовать «Подключение» после смены настроек из меню (без VPN, D-95). */
    private var redrawConnect: () -> Unit = {}

    fun show() {
        Theme.apply(prefs.theme, System.getenv(), System.getProperty("user.home"))
        lateinit var servers: ServersPanel
        lateinit var subscriptions: SubscriptionsPanel
        lateinit var connect: ConnectPanel
        var relays: RelaysPanel? = null
        lateinit var tabs: JTabbedPane
        val changed = {
            servers.refresh()
            connect.render(session.status.value)
        }
        subscriptions = SubscriptionsPanel(graph, scope, changed, { run ->
            if (run.needsReconnect(session.connectedProfile())) session.reconnectIfConnected()
        }) { session.reconnectIfConnected() }
        val import = ImportFlow(graph, scope, { frame }, subscriptions, changed, {
            relays?.let {
                it.reload()
                tabs.selectedComponent = it
            }
        }) { session.reconnectIfConnected() }
        connect = ConnectPanel(graph, session, prefs, import::fromClipboard)
        redrawConnect = { connect.render(session.status.value) }
        servers = ServersPanel(graph, prefs, scope, { session.status.value }) {
            session.reconnectIfConnected()
            relays?.render()
        }
        val log = LogPanel(graph)
        val network = NetworkPanel(graph.networkCheck, scope)
        // Раздача и устройства раздачи — только на Linux (D-84, D-85); на Windows их нет (D-97).
        val share = graph.shares?.let { SharePanel(graph, session) }
        relays = graph.relayNetworks?.let { RelaysPanel(graph, it, session, prefs, scope, import::fromClipboard) }
        val relaysPanel = relays
        tabs = JTabbedPane().apply {
            // Без своего фона за ярлыками вкладок видна светлая подложка окна.
            isOpaque = true
            background = Theme.palette.bg
            addTab("Подключение", connect)
            addTab("Серверы", servers)
            addTab("Подписки", subscriptions)
            addTab("Сеть", network)
            share?.let { addTab("Раздача", it) }
            relaysPanel?.let { addTab("Устройства раздачи", it) }
            addTab("Журнал", log)
            addChangeListener {
                when (selectedComponent) {
                    servers -> servers.refresh()
                    subscriptions -> subscriptions.reload()
                    log -> log.reload()
                    share -> share.reload()
                    relaysPanel -> relaysPanel.reload()
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
        scope.launch(Edt) { session.usageAlert.collect(connect::renderUsageAlert) }
        share?.let { panel -> scope.launch(Edt) { session.share.collect { panel.render(session.status.value, it) } } }
        scope.launch(Edt) {
            session.status.collect { s ->
                connect.render(s)
                share?.render(s, session.share.value)
                relaysPanel?.render()
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
                // Разбиение ClientHello к серверу (D-68, D-81): действует сразу — туннель переподключается.
                add(
                    JCheckBoxMenuItem("Разбивать начало соединения с сервером", prefs.splitClientHello).apply {
                        toolTipText = "TLS ClientHello к серверу уходит мелкими частями. Может помочь против фильтров, которые ищут там " +
                            "имя сайта; помогает не везде и добавляет десятки миллисекунд к подключению. Только серверы с TLS или " +
                            "REALITY поверх TCP; сервер не принял — DPpass повторяет без разбиения"
                        addActionListener {
                            prefs.splitClientHello = isSelected
                            graph.core.log.info("client_hello_split_set", "on" to isSelected)
                            session.reconnectIfConnected()
                        }
                    },
                )
                // Сайты напрямую с разбиением (D-72, D-82): список ПК; действует сразу.
                add(JMenuItem("Сайты напрямую с разбиением…").apply { addActionListener { SplitSitesDialog.show(frame, graph, prefs, session) } })
                // Свои списки сайтов (D-93): напрямую, через туннель, блокировать; действует сразу.
                add(
                    JMenuItem("Свои списки сайтов…").apply {
                        addActionListener { SiteListsDialog.show(frame, graph.core, scope, { session.reconnectIfConnected() }) }
                    },
                )
                // Подключение без VPN (D-95): локальный прокси с паролем вместо TUN.
                add(
                    JMenuItem("Подключение без VPN…").apply {
                        addActionListener { LocalProxyDialog.show(frame, graph.core, { session.reconnectIfConnected() }) { redrawConnect() } }
                    },
                )
                // Без сервера (D-73, D-83): остальные сайты и DNS; приложения — все (Linux и Windows их не различают).
                add(serverlessMenu())
                // Проверка новой сети при поднятом туннеле (D-80): выключено — только по кнопке на «Сети».
                add(
                    JCheckBoxMenuItem("Проверять сеть при её смене", prefs.checkOnNetworkChange).apply {
                        toolTipText = "Через 20 с после смены сети — та же проверка, что на вкладке «Сеть», не больше 4 раз в час; " +
                            "ориентиры видят адрес ПК в новой сети"
                        // На Windows пробы при туннеле шли бы через него (D-97): пункт есть, но не действует — и сказано почему.
                        if (!graph.host.checksUnderTunnel) {
                            isEnabled = false
                            toolTipText = "На Windows проверка сети — только без туннеля: через туннель она мерила бы сервер, а не сеть (D-97)"
                        }
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

    /**
     * «Без сервера» (D-83): когда серверов нет, а в «Сайтах напрямую с
     * разбиением» есть записи (или остальные сайты — с разбиением),
     * «Подключить» поднимает туннель без сервера. Смена выбора при туннеле
     * без сервера — переподключение.
     */
    private fun serverlessMenu(): JMenu = JMenu("Без сервера").apply {
        toolTipText = "Есть серверы — подключение только через них. Без сервера помогает только против фильтров, " +
            "которые ищут имя сайта: закрытый адрес так не открыть"
        /** Группа выбора: каждый пункт меняет только своё поле нынешней настройки — на момент нажатия. */
        fun group(title: String, options: List<Pair<String, (ServerlessSettings) -> ServerlessSettings>>) {
            add(JMenuItem(title).apply { isEnabled = false })
            val g = ButtonGroup()
            for ((label, change) in options) {
                val current = prefs.serverless
                val item = JRadioButtonMenuItem(label, change(current) == current).apply {
                    addActionListener {
                        val next = change(prefs.serverless)
                        prefs.serverless = next
                        graph.core.log.info("serverless_set", "rest" to Safe(next.rest.wire), "dns" to Safe(next.dns.wire))
                        if (session.connectedProfile() == ServerlessPlan.PROFILE_ID) session.reconnectIfConnected()
                    }
                }
                g.add(item)
                add(item)
            }
        }
        group(
            "Остальные сайты",
            listOf(
                "Напрямую, как без VPN" to { s -> s.copy(rest = ServerlessSettings.Rest.DIRECT) },
                "С разбиением" to { s -> s.copy(rest = ServerlessSettings.Rest.SPLIT) },
            ),
        )
        addSeparator()
        group(
            "DNS",
            listOf(
                "DoH напрямую — мимо резолвера оператора" to { s -> s.copy(dns = ServerlessSettings.Dns.DOH) },
                "Системный — как резолвит система" to { s -> s.copy(dns = ServerlessSettings.Dns.SYSTEM) },
            ),
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
