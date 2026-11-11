package com.dpsmpx.dppass.desktop.ui

import com.dpsmpx.dppass.connection.RelayDevice
import com.dpsmpx.dppass.connection.RelayDraft
import com.dpsmpx.dppass.desktop.DesktopGraph
import com.dpsmpx.dppass.desktop.DesktopPrefs
import com.dpsmpx.dppass.desktop.DesktopSession
import com.dpsmpx.dppass.desktop.RelayNetworks
import com.dpsmpx.dppass.desktop.RelayPairing
import com.dpsmpx.dppass.desktop.SessionStatus
import com.dpsmpx.dppass.diagnostics.Diagnostic
import com.dpsmpx.dppass.diagnostics.Outcome
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.awt.BorderLayout
import java.awt.FlowLayout
import java.awt.GridBagConstraints
import java.awt.GridBagLayout
import java.awt.Insets
import javax.swing.Box
import javax.swing.ButtonGroup
import javax.swing.JComponent
import javax.swing.JLabel
import javax.swing.JOptionPane
import javax.swing.JPanel
import javax.swing.JRadioButton
import javax.swing.JTextField

/**
 * «Устройства раздачи» (D-85, к D-55): подключение ПК через телефон с
 * DPpass, который раздаёт свой туннель (D-51). Доверенное устройство
 * выбирается одним нажатием — и сразу подключение. Какие из них рядом,
 * видно по шлюзам сетей ПК: DPpass спрашивает шлюз по протоколу входа,
 * ничего не объявляя в сети. Добавить — сопряжением по коду (D-56),
 * вручную или ссылкой «Поделиться входом» с того телефона.
 */
class RelaysPanel(
    private val graph: DesktopGraph,
    /** Сети ПК для поиска и сопряжения (D-85, на Windows — D-102). */
    private val nets: RelayNetworks,
    private val session: DesktopSession,
    private val prefs: DesktopPrefs,
    private val scope: CoroutineScope,
    private val import: () -> Unit,
) : JPanel(BorderLayout()) {
    private val devices = rows()
    private val networks = rows()
    private val status = Widgets.caption(" ")
    private val problem = Widgets.Banner(error = true)
    private var found: Map<String, RelayNetworks.Target> = emptyMap()
    private var gateways: List<RelayNetworks.Gateway> = emptyList()
    private var checking = false
    private var scan: Job? = null
    private var pairing: Job? = null

    init {
        background = Theme.palette.bg
        border = Widgets.pad(4)
        val column = Widgets.Column()
        column.line(Widgets.title("Устройства раздачи").also { it.border = Widgets.pad(1) })
        column.line(Widgets.still(Widgets.note()).apply { text = INTRO })
        column.add(Box.createVerticalStrut(Widgets.STEP * 4))
        column.line(Widgets.title("Доверенные устройства").also { it.border = Widgets.pad(1) })
        column.line(devices)
        column.line(
            JPanel(FlowLayout(FlowLayout.LEFT, Widgets.STEP * 2, Widgets.STEP * 2)).apply {
                isOpaque = false
                add(Widgets.button("Сопряжение с устройством") { pair() })
                add(Widgets.button("Добавить вручную…") { addDevice(null) })
            },
        )
        // Третья кнопка — своим рядом: FlowLayout в колонке не переносит ряд по высоте.
        column.line(
            JPanel(FlowLayout(FlowLayout.LEFT, Widgets.STEP * 2, 0)).apply {
                isOpaque = false
                add(Widgets.button("Импорт из буфера обмена…") { import() })
            },
        )
        column.line(status)
        column.line(problem)
        column.add(Box.createVerticalStrut(Widgets.STEP * 4))
        column.line(Widgets.title("Сети рядом").also { it.border = Widgets.pad(1) })
        column.line(networks)
        column.line(
            JPanel(FlowLayout(FlowLayout.LEFT, 0, Widgets.STEP * 2)).apply {
                isOpaque = false
                add(Widgets.button("Искать снова") { rescan() })
            },
        )
        column.add(Box.createVerticalStrut(Widgets.STEP * 4))
        column.line(Widgets.title("Важно знать").also { it.border = Widgets.pad(1) })
        column.line(Widgets.still(Widgets.note()).apply { text = LIMITS })
        add(column.scroll(), BorderLayout.CENTER)
        render()
    }

    /** Вкладку открыли или список сменился (импорт ссылки): заново — список и поиск рядом. */
    fun reload() {
        render()
        rescan()
    }

    fun render() {
        devices.removeAll()
        networks.removeAll()
        val list = when (val l = graph.core.relays.list()) {
            is Outcome.Failure -> {
                devices.add(Widgets.caption(l.errors.first().message), cell(0, 0, 3))
                refreshLayout()
                return
            }
            is Outcome.Success -> l.value
        }
        val selected = prefs.selectedRelay?.takeIf { id -> list.any { it.id == id } }
        val group = ButtonGroup()
        fun radio(text: String, on: Boolean, id: String?) = JRadioButton(text, on).apply {
            isOpaque = false
            foreground = Theme.palette.text
            group.add(this)
            addActionListener { choose(id) }
        }
        devices.add(radio("Не через устройство", selected == null, null), cell(0, 0))
        devices.add(Widgets.caption("Серверы подписки, как обычно"), cell(1, 0, 2))
        for ((i, d) in list.withIndex()) {
            val row = i + 1
            val note = found[d.id]?.medium?.let { "Рядом: ${medium(it)}" } ?: if (checking) "Ищу…" else "Не найдено в сетях ПК"
            devices.add(radio(d.name, selected == d.id, d.id), cell(0, row))
            devices.add(Widgets.caption(note), cell(1, row))
            devices.add(
                JPanel(FlowLayout(FlowLayout.LEFT, Widgets.STEP * 2, 0)).apply {
                    isOpaque = false
                    add(Widgets.button("Переименовать…") { rename(d) })
                    add(Widgets.button("Удалить") { delete(d) })
                },
                cell(2, row),
            )
        }
        // Сети рядом: шлюзы, где не ответило ни одно известное устройство.
        val others = gateways.filter { g -> found.values.none { it.address == g.address } }
        when {
            checking && gateways.isEmpty() -> networks.add(Widgets.caption("Ищу…"), cell(0, 0))
            gateways.isEmpty() -> networks.add(Widgets.caption("ПК не подключён к точке доступа, USB- или Bluetooth-модему другого устройства."), cell(0, 0))
            others.isEmpty() -> networks.add(Widgets.caption("Других шлюзов нет: все ответившие — уже в списке."), cell(0, 0))
            else -> for ((i, g) in others.withIndex()) {
                networks.add(JLabel("Шлюз ${medium(g.medium)} ${g.address}").apply { foreground = Theme.palette.text }, cell(0, i))
                networks.add(Widgets.button("Добавить…") { addDevice("Устройство по ${medium(g.medium)}") }, cell(1, i))
            }
        }
        refreshLayout()
    }

    /** Какие устройства рядом и какие шлюзы есть: в фоне, по короткому соединению на кандидата. */
    private fun rescan() {
        val list = graph.core.relays.list().valueOrNull().orEmpty()
        scan?.cancel()
        checking = true
        render()
        scan = scope.launch(Edt) {
            val (gws, answered) = withContext(Dispatchers.IO) {
                val gws = nets.gateways()
                val answered = if (gws.isEmpty() && list.none { it.address != null }) {
                    emptyMap()
                } else {
                    list.mapNotNull { d -> nets.locate(d).valueOrNull()?.let { d.id to it } }.toMap()
                }
                gws to answered
            }
            gateways = gws
            found = answered
            checking = false
            render()
        }
    }

    /**
     * Выбор сохраняется. Туннель есть — переподключение через выбранное; нет —
     * подключение сразу; идёт подключение — выбор в силе со следующего.
     */
    private fun choose(id: String?) {
        if (id == prefs.selectedRelay) return
        prefs.selectedRelay = id
        graph.core.log.info("relay_selected", "on" to (id != null))
        when (session.status.value) {
            is SessionStatus.Connected -> session.reconnectIfConnected()
            is SessionStatus.Connecting, SessionStatus.Disconnecting -> Unit
            else -> if (id != null) session.connect(prefs.selectedServer)
        }
        render()
    }

    /**
     * Сопряжение (D-56): раздающий телефон ждёт на шлюзе одной из сетей ПК.
     * Код — окном; подтвердили оба — устройство в списке и выбрано.
     */
    private fun pair() {
        if (pairing?.isActive == true) return
        problem.show(null)
        status.text = "Ищу телефон, который ждёт сопряжения…"
        pairing = scope.launch(Edt) {
            val r = withContext(Dispatchers.IO) {
                RelayPairing.pair(nets, graph.core.relays, graph.core.log) { code ->
                    withContext(Edt) {
                        status.text = "Телефон найден — сверьте код"
                        codeMatches(code)
                    }
                }
            }
            status.text = " "
            when (r) {
                is Outcome.Failure -> fail(r.errors.first(), r.errors.drop(1))
                is Outcome.Success -> {
                    status.text = "Устройство сопряжено и выбрано"
                    choose(r.value.id)
                    rescan()
                }
            }
        }
    }

    private fun codeMatches(code: String): Boolean {
        val options = arrayOf("Совпадает", "Не совпадает")
        val answer = JOptionPane.showOptionDialog(
            this,
            "${code.chunked(CODE_GROUP).joinToString(" ")}\n\nНа телефоне тот же код?",
            "Код сопряжения",
            JOptionPane.YES_NO_OPTION,
            JOptionPane.QUESTION_MESSAGE,
            null,
            options,
            options[1],
        )
        return answer == 0
    }

    /**
     * Ввод вручную: имя, адрес (пусто — шлюз сети), порт, логин, пароль — с
     * экрана «Раздача туннеля» того телефона. Отказ — причина, и окно
     * открывается снова с тем же вводом: опечатку можно исправить.
     */
    private fun addDevice(prefillName: String?) {
        val name = JTextField(prefillName ?: DEFAULT_NAME, FIELD_COLUMNS)
        val address = JTextField(FIELD_COLUMNS)
        val port = JTextField(FIELD_COLUMNS)
        val user = JTextField(FIELD_COLUMNS)
        val password = JTextField(FIELD_COLUMNS)
        val form = JPanel(GridBagLayout()).apply {
            val fields = listOf("Имя" to name, "Адрес (пусто — шлюз сети)" to address, "Порт" to port, "Ключ сервера" to user, "Ключ клиента" to password)
            for ((i, f) in fields.withIndex()) {
                add(JLabel(f.first), cell(0, i))
                add(f.second, cell(1, i))
            }
            add(Widgets.still(Widgets.note()).apply { text = ADD_NOTE; columns = FIELD_COLUMNS * 2 }, cell(0, fields.size, 2))
        }
        while (true) {
            val answer = JOptionPane.showConfirmDialog(this, form, "Устройство раздачи", JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE)
            if (answer != JOptionPane.OK_OPTION) return
            val draft = RelayDraft(name.text, address.text, port.text.trim().toIntOrNull() ?: 0, user.text, password.text)
            when (val r = graph.core.relays.add(draft)) {
                is Outcome.Failure -> JOptionPane.showMessageDialog(
                    this,
                    r.errors.joinToString("\n") { it.message },
                    "Устройство не добавлено",
                    JOptionPane.WARNING_MESSAGE,
                )
                is Outcome.Success -> {
                    status.text = "Устройство добавлено"
                    reload()
                    return
                }
            }
        }
    }

    private fun rename(d: RelayDevice) {
        val name = JOptionPane.showInputDialog(this, "Имя", d.name) ?: return
        when (val r = graph.core.relays.rename(d.id, name)) {
            is Outcome.Failure -> problem.show(Widgets.describe(r.errors.first()))
            is Outcome.Success -> render()
        }
    }

    private fun delete(d: RelayDevice) {
        val answer = JOptionPane.showConfirmDialog(this, "Убрать «${d.name}» из доверенных устройств?", "Удалить", JOptionPane.OK_CANCEL_OPTION)
        if (answer != JOptionPane.OK_OPTION) return
        when (val r = graph.core.relays.remove(d.id)) {
            is Outcome.Failure -> problem.show(Widgets.describe(r.errors.first()))
            is Outcome.Success -> if (prefs.selectedRelay == d.id) choose(null) else render()
        }
    }

    private fun fail(d: Diagnostic, more: List<Diagnostic> = emptyList()) {
        (listOf(d) + more).forEach(graph.core.log::diagnostic)
        problem.show(Widgets.describe(d))
        refreshLayout()
    }

    private fun refreshLayout() {
        // Пустая колонка забирает лишнюю ширину: строки — у левого края, а не по центру.
        for (rows in listOf(devices, networks)) rows.add(Box.createHorizontalGlue(), GridBagConstraints().apply { gridx = GLUE_COLUMN; weightx = 1.0 })
        revalidate()
        repaint()
    }

    private companion object {
        fun rows() = JPanel(GridBagLayout()).apply { isOpaque = false }

        fun cell(x: Int, y: Int, width: Int = 1) = GridBagConstraints().apply {
            gridx = x
            gridy = y
            gridwidth = width
            anchor = GridBagConstraints.WEST
            insets = Insets(Widgets.STEP, 0, Widgets.STEP, Widgets.STEP * 4)
        }

        fun medium(m: RelayNetworks.Medium): String = when (m) {
            RelayNetworks.Medium.WIFI -> "Wi-Fi"
            RelayNetworks.Medium.USB -> "USB"
            RelayNetworks.Medium.BLUETOOTH -> "Bluetooth"
            RelayNetworks.Medium.WIRED -> "провод"
        }

        const val FIELD_COLUMNS = 20
        const val GLUE_COLUMN = 9
        const val CODE_GROUP = 3
        const val DEFAULT_NAME = RelayPairing.DEFAULT_NAME

        const val INTRO = "Подключение через телефон с DPpass, который раздаёт свой туннель: подключите ПК к его точке доступа Wi-Fi, " +
            "USB- или Bluetooth-модему и выберите его здесь."

        const val ADD_NOTE = "Порт и ключи — на том телефоне: «Настройки» → «Раздача туннеля». Проще — сопряжение по коду " +
            "или «Поделиться входом» там и «Импорт из буфера обмена» здесь."

        const val LIMITS = "• На том телефоне DPpass должен быть подключён, а «Раздача туннеля» — включена.\n" +
            "• На обоих устройствах нужен DPpass с защищённым форматом; старые настройки требуют повторного сопряжения.\n" +
            "• Подключение идёт только через выбранное устройство: если его нет рядом, DPpass скажет почему, а не подключится к " +
            "другим серверам.\n" +
            "• USB-модем телефона ПК видит как проводную сеть, если у системы ПК есть драйвер RNDIS или NCM; Bluetooth-модем " +
            "подключается в настройках Bluetooth ПК — DPpass этого не делает."
    }
}
