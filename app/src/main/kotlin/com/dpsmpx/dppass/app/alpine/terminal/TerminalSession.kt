package com.dpsmpx.dppass.app.alpine.terminal

/** Канал к программе на target (D-71): ввод, размер окна, закрытие. */
interface TerminalTransport {
    fun write(bytes: ByteArray)
    fun resize(cols: Int, rows: Int)
    fun close()
}

/** События сессии для экрана: вызываются из потока вывода, не под замком. */
interface TerminalListener {
    fun changed() {}
    fun title(title: String) {}
    fun bell() {}
    /** Программа просит записать текст в буфер обмена (OSC 52): экран спрашивает человека. */
    fun clipboard(text: String) {}
    fun closed(exitCode: Int?) {}
}

/**
 * Сессия терминала (D-71): эмулятор под замком и канал к программе.
 * Вывод программы ([output]) и чтение экрана ([read]) — из разных
 * потоков, поэтому эмулятор трогается только под замком; ответы
 * эмулятора программе (DA, DSR) уходят в канал после замка, чтобы
 * медленная сеть не держала перерисовку. История экрана — только в
 * памяти: через терминал проходит вход в Claude (D-27).
 */
class TerminalSession(
    cols: Int,
    rows: Int,
    scrollbackMax: Int = 5_000,
    private val listener: TerminalListener = object : TerminalListener {},
) {
    private val lock = Any()
    private val replies = ArrayList<ByteArray>()
    private val events = ArrayList<() -> Unit>()

    @Volatile
    private var transport: TerminalTransport? = null

    private val emulator = TerminalEmulator(
        cols, rows, scrollbackMax,
        host = object : TerminalHost {
            override fun write(bytes: ByteArray) {
                replies += bytes
            }
            override fun title(title: String) {
                events += { listener.title(title) }
            }
            override fun bell() {
                events += { listener.bell() }
            }
            override fun clipboard(text: String) {
                events += { listener.clipboard(text) }
            }
        },
    )

    val isConnected: Boolean get() = transport != null

    /** Канал открыт: размер окна сообщается ему сразу. */
    fun attach(t: TerminalTransport) {
        val (c, r) = read { it.cols to it.rows }
        transport = t
        t.resize(c, r)
    }

    /** Вывод программы. */
    fun output(bytes: ByteArray, off: Int = 0, len: Int = bytes.size) {
        val out: List<ByteArray>
        val ev: List<() -> Unit>
        synchronized(lock) {
            emulator.feed(bytes, off, len)
            out = replies.toList()
            ev = events.toList()
            replies.clear()
            events.clear()
        }
        val t = transport
        if (t != null) out.forEach(t::write)
        ev.forEach { it() }
        listener.changed()
    }

    /** Канал закрылся (выход программы, обрыв связи). */
    fun closed(exitCode: Int?) {
        transport = null
        listener.closed(exitCode)
    }

    /** Байты ввода программе; канала нет — ввод теряется, а не копится. */
    fun send(bytes: ByteArray) {
        if (bytes.isNotEmpty()) transport?.write(bytes)
    }

    fun key(key: Key, mods: Int = 0) = send(read { KeyEncoder.key(key, mods, it) })

    fun type(text: String, mods: Int = 0) {
        if (mods == 0) send(text.toByteArray(Charsets.UTF_8)) else text.codePoints().forEach { send(KeyEncoder.char(it, mods)) }
    }

    fun paste(text: String) = send(read { KeyEncoder.paste(text, it) })

    fun mouse(button: MouseButton, col: Int, row: Int, pressed: Boolean, motion: Boolean, mods: Int = 0) {
        read { KeyEncoder.mouse(button, col, row, pressed, motion, mods, it) }?.let(::send)
    }

    fun focus(gained: Boolean) {
        read { KeyEncoder.focus(gained, it) }?.let(::send)
    }

    /** Новый размер окна: экран перестраивается, программа узнаёт по SIGWINCH. */
    fun resize(cols: Int, rows: Int) {
        synchronized(lock) { emulator.resize(cols, rows) }
        transport?.resize(cols, rows)
        listener.changed()
    }

    /** Чтение экрана под замком (перерисовка, выделение). */
    fun <T> read(block: (TerminalEmulator) -> T): T = synchronized(lock) { block(emulator) }

    fun close() {
        transport?.close()
        transport = null
    }
}
