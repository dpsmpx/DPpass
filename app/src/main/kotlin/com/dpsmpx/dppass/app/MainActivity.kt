package com.dpsmpx.dppass.app

import android.Manifest
import android.annotation.SuppressLint
import android.app.Activity
import android.app.AlertDialog
import android.content.Intent
import android.content.pm.PackageManager
import android.content.res.ColorStateList
import android.net.Uri
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.view.Gravity
import android.view.View
import android.view.WindowInsets
import android.view.WindowManager
import android.widget.FrameLayout
import android.widget.ImageView
import android.widget.LinearLayout
import android.widget.TextView
import android.widget.Toast
import android.window.OnBackInvokedCallback
import android.window.OnBackInvokedDispatcher
import com.dpsmpx.dppass.R
import com.dpsmpx.dppass.app.ui.ConnectScreen
import com.dpsmpx.dppass.app.ui.Host
import com.dpsmpx.dppass.app.ui.ImportFlow
import com.dpsmpx.dppass.app.ui.MainThread
import com.dpsmpx.dppass.app.ui.Screen
import com.dpsmpx.dppass.app.ui.ServersScreen
import com.dpsmpx.dppass.app.ui.SettingsScreen
import com.dpsmpx.dppass.app.ui.StorageLost
import com.dpsmpx.dppass.app.ui.SubscriptionsScreen
import com.dpsmpx.dppass.app.ui.Ui
import com.dpsmpx.dppass.diagnostics.DiagCode
import com.dpsmpx.dppass.diagnostics.Diagnostic
import com.dpsmpx.dppass.diagnostics.Outcome
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.IOException

/**
 * Интерфейс DPpass (D-34): одна `Activity`, четыре вкладки — «Подключение»,
 * «Серверы», «Подписки», «Настройки» — и вложенные экраны поверх них
 * (приложения, журнал, «О программе»). Граф зависимостей собирается в фоне
 * (перенос геоданных, загрузка ядра); до этого экраны пустые, но живые.
 *
 * Перерисовывается только видимый экран; скрытый — при показе.
 * Текст из «Поделиться» (D-42) распознаётся и показывается сводкой — без
 * нажатия пользователя ничего не применяется (T13).
 *
 * Экраны показывают конфигурацию и её серверы — снимки экрана запрещены
 * (`FLAG_SECURE`, docs/SECURITY_MODEL.md, T9).
 */
class MainActivity : Activity(), Host {
    override val activity: Activity get() = this
    override val scope: CoroutineScope = CoroutineScope(SupervisorJob() + MainThread)
    override val prefs: AppPrefs by lazy { AppPrefs(this) }

    @Volatile
    override var graph: AppGraph.Graph? = null
        private set

    private lateinit var tabs: List<Screen>
    private val stack = ArrayList<Screen>()
    private lateinit var content: FrameLayout
    private lateinit var overlay: FrameLayout
    private lateinit var nav: LinearLayout
    private var tab = Host.TAB_CONNECT
    private var askedNotifications = false
    private var pendingImport: String? = null

    /** Документ экспорта до выбора файла (D-11): только в памяти, после записи — забыт. */
    private var pendingExport: String? = null
    private var backCallback: OnBackInvokedCallback? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)
        tabs = listOf(ConnectScreen(this), ServersScreen(this), SubscriptionsScreen(this), SettingsScreen(this))
        content = FrameLayout(this)
        tabs.forEach { content.addView(it.view, FrameLayout.LayoutParams(FrameLayout.LayoutParams.MATCH_PARENT, FrameLayout.LayoutParams.MATCH_PARENT)) }
        overlay = FrameLayout(this).apply { visibility = View.GONE }
        nav = navigation()
        val main = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            addView(content, LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, 0, 1f))
            addView(nav, LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT))
        }
        val root = FrameLayout(this).apply {
            setBackgroundColor(getColor(R.color.bg))
            addView(main, FrameLayout.LayoutParams(FrameLayout.LayoutParams.MATCH_PARENT, FrameLayout.LayoutParams.MATCH_PARENT))
            addView(this@MainActivity.overlay, FrameLayout.LayoutParams(FrameLayout.LayoutParams.MATCH_PARENT, FrameLayout.LayoutParams.MATCH_PARENT))
        }
        edgeToEdge(root)
        setContentView(root)
        DeviceLog.log.info("activity_create")
        showTab(prefs.tab.coerceIn(0, tabs.lastIndex))
        pendingImport = sharedText(intent)
        sharedImage(intent)?.let(::readQr)
        scope.launch {
            val (g, restored) = withContext(Dispatchers.IO) {
                val g = AppGraph.graph(this@MainActivity)
                g to if (g.core.activation.state.activeConfig == null) g.core.restore() else emptyList()
            }
            graph = g
            changed()
            // Сохранённое не прочитать — ключ утрачен (D-19): сказать сразу и с выходом, а не пустым экраном.
            StorageLost.find(restored)?.let { problem(getString(R.string.storage_lost_title), it) }
            pendingImport?.let {
                pendingImport = null
                importText(it)
            }
        }
        scope.launch { TunnelState.status.collect { changed() } }
        // Итог пробы IPv6 (D-66) приходит позже подключения — «Почему этот сервер» его покажет.
        scope.launch { TunnelState.ipv6.collect { changed() } }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        sharedText(intent)?.let(::deliver)
        sharedImage(intent)?.let(::readQr)
    }

    /** Граф ещё собирается — текст подождёт его (onCreate разберёт [pendingImport]). */
    private fun deliver(text: String) {
        if (graph != null) importText(text) else pendingImport = text
    }

    /** Текст из «Поделиться» (D-42); не больше документа DPpass. */
    private fun sharedText(intent: Intent?): String? {
        if (intent?.action != Intent.ACTION_SEND || intent.type != "text/plain") return null
        return intent.getStringExtra(Intent.EXTRA_TEXT)?.takeIf { it.isNotBlank() && it.length <= ImportFlow.MAX_FILE_BYTES }
    }

    /** Картинка из «Поделиться» (D-65): QR на ней распознаётся, как выбранный файл. */
    private fun sharedImage(intent: Intent?): Uri? {
        if (intent?.action != Intent.ACTION_SEND || intent.type?.startsWith("image/") != true) return null
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            intent.getParcelableExtra(Intent.EXTRA_STREAM, Uri::class.java)
        } else {
            @Suppress("DEPRECATION") // типизированный вариант — только с API 33
            intent.getParcelableExtra(Intent.EXTRA_STREAM) as? Uri
        }
    }

    /**
     * Android 15+ рисует приложение под системными панелями всегда; с API 30
     * так и здесь — отступы по вставкам окна (и клавиатуры). На API 26–29 окно
     * само оставляет место под панели.
     */
    private fun edgeToEdge(root: View) {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.R) return
        window.setDecorFitsSystemWindows(false)
        root.setOnApplyWindowInsetsListener { _, insets ->
            val bars = insets.getInsets(WindowInsets.Type.systemBars() or WindowInsets.Type.displayCutout())
            val ime = insets.getInsets(WindowInsets.Type.ime())
            content.setPadding(bars.left, bars.top, bars.right, 0)
            nav.setPadding(bars.left, 0, bars.right, bars.bottom)
            overlay.setPadding(bars.left, bars.top, bars.right, maxOf(bars.bottom, ime.bottom))
            WindowInsets.CONSUMED
        }
    }

    private fun navigation(): LinearLayout = LinearLayout(this).apply {
        orientation = LinearLayout.HORIZONTAL
        setBackgroundColor(getColor(R.color.surface))
        elevation = Ui.dpF(context, 2f)
        val items = listOf(
            R.string.tab_connect to R.drawable.ic_power,
            R.string.tab_servers to R.drawable.ic_servers,
            R.string.tab_subscriptions to R.drawable.ic_subscriptions,
            R.string.tab_settings to R.drawable.ic_settings,
        )
        items.forEachIndexed { i, (label, icon) ->
            val item = LinearLayout(this@MainActivity).apply {
                orientation = LinearLayout.VERTICAL
                gravity = Gravity.CENTER
                minimumHeight = Ui.dp(context, 64)
                setPadding(0, Ui.dp(context, 8), 0, Ui.dp(context, 8))
                setBackgroundResource(R.drawable.bg_row)
                isClickable = true
                isFocusable = true
                contentDescription = getString(label)
                setOnClickListener { showTab(i) }
                val pill = FrameLayout(context).apply {
                    setBackgroundResource(R.drawable.bg_pill)
                    addView(
                        ImageView(context).apply {
                            setImageResource(icon)
                            importantForAccessibility = View.IMPORTANT_FOR_ACCESSIBILITY_NO
                        },
                        FrameLayout.LayoutParams(Ui.dp(context, 24), Ui.dp(context, 24), Gravity.CENTER),
                    )
                }
                addView(pill, LinearLayout.LayoutParams(Ui.dp(context, 56), Ui.dp(context, 32)))
                addView(
                    Ui.text(context, R.style.Text_DPpass_Caption, getString(label)).apply {
                        importantForAccessibility = View.IMPORTANT_FOR_ACCESSIBILITY_NO
                        maxLines = 1
                    },
                    LinearLayout.LayoutParams(LinearLayout.LayoutParams.WRAP_CONTENT, LinearLayout.LayoutParams.WRAP_CONTENT).apply {
                        topMargin = Ui.dp(context, 4)
                    },
                )
            }
            addView(item, LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f))
        }
    }

    override fun showTab(tab: Int) {
        while (stack.isNotEmpty()) pop()
        val previous = this.tab
        this.tab = tab
        prefs.tab = tab
        tabs.forEachIndexed { i, s ->
            val on = i == tab
            if (on && s.view.visibility != View.VISIBLE) {
                s.view.alpha = 0f
                s.view.visibility = View.VISIBLE
                s.view.animate().alpha(1f).setDuration(TRANSITION_MILLIS).start()
            } else if (!on) {
                s.view.visibility = View.GONE
            }
        }
        if (previous != tab) tabs[previous].onHidden()
        for (i in 0 until nav.childCount) {
            val item = nav.getChildAt(i) as LinearLayout
            val on = i == tab
            item.isSelected = on
            val pill = item.getChildAt(0) as FrameLayout
            pill.backgroundTintList = ColorStateList.valueOf(getColor(if (on) R.color.primary_container else android.R.color.transparent))
            (pill.getChildAt(0) as ImageView).imageTintList =
                ColorStateList.valueOf(getColor(if (on) R.color.on_primary_container else R.color.text_secondary))
            (item.getChildAt(1) as TextView).setTextColor(getColor(if (on) R.color.text else R.color.text_secondary))
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) item.stateDescription = if (on) getString(R.string.a11y_selected) else null
        }
        val visible = tabs[tab]
        visible.render(TunnelState.status.value)
        visible.onShown()
    }

    override fun push(screen: Screen) {
        (stack.lastOrNull() ?: tabs[tab]).onHidden()
        stack += screen
        overlay.removeAllViews()
        overlay.addView(screen.view, FrameLayout.LayoutParams(FrameLayout.LayoutParams.MATCH_PARENT, FrameLayout.LayoutParams.MATCH_PARENT))
        overlay.visibility = View.VISIBLE
        screen.view.translationX = Ui.dpF(this, 24f)
        screen.view.alpha = 0f
        screen.view.animate().translationX(0f).alpha(1f).setDuration(TRANSITION_MILLIS).start()
        screen.render(TunnelState.status.value)
        screen.onShown()
        updateBack()
    }

    override fun pop() {
        val top = stack.removeLastOrNull() ?: return
        top.onHidden()
        overlay.removeAllViews()
        val next = stack.lastOrNull()
        if (next != null) {
            overlay.addView(next.view, FrameLayout.LayoutParams(FrameLayout.LayoutParams.MATCH_PARENT, FrameLayout.LayoutParams.MATCH_PARENT))
            next.render(TunnelState.status.value)
            next.onShown()
        } else {
            overlay.visibility = View.GONE
            tabs[tab].render(TunnelState.status.value)
            tabs[tab].onShown()
        }
        updateBack()
    }

    /** «Назад» закрывает вложенный экран; на вкладке — системное поведение (выход). */
    private fun updateBack() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU) return
        val dispatcher = onBackInvokedDispatcher
        if (stack.isNotEmpty() && backCallback == null) {
            val cb = OnBackInvokedCallback { pop() }
            dispatcher.registerOnBackInvokedCallback(OnBackInvokedDispatcher.PRIORITY_DEFAULT, cb)
            backCallback = cb
        } else if (stack.isEmpty()) {
            backCallback?.let(dispatcher::unregisterOnBackInvokedCallback)
            backCallback = null
        }
    }

    // До Android 13 «Назад» (кнопка и жест) приходит только сюда; с API 33 — OnBackInvokedCallback
    // (updateBack, enableOnBackInvokedCallback в манифесте). OnBackPressedDispatcher — только в AndroidX (D-34).
    @SuppressLint("GestureBackNavigation")
    @Deprecated("До Android 13 «Назад» приходит сюда; с API 33 — OnBackInvokedCallback (updateBack)")
    override fun onBackPressed() {
        if (stack.isNotEmpty()) {
            pop()
        } else {
            @Suppress("DEPRECATION")
            super.onBackPressed()
        }
    }

    override fun changed() {
        val status = TunnelState.status.value
        (stack.lastOrNull() ?: tabs[tab]).render(status)
    }

    override fun toast(text: CharSequence) {
        Toast.makeText(this, text, Toast.LENGTH_LONG).show()
    }

    override fun problem(title: CharSequence, reason: Diagnostic) {
        // Причина целиком, с текстом ядра: на устройстве её больше негде увидеть (D-22).
        val dialog = AlertDialog.Builder(this)
            .setTitle(title)
            .setMessage(reason.renderWithCauses().joinToString("\n"))
            .setPositiveButton(android.R.string.ok, null)
        // Ключ данных утрачен (D-19): выход — сброс хранилища, только по нажатию и с подтверждением.
        if (StorageLost.isLost(reason)) dialog.setNeutralButton(R.string.storage_reset) { _, _ -> confirmStorageReset() }
        Ui.secure(dialog.show())
    }

    /**
     * Сброс хранилища (D-19, `DPpassCore.resetStorage`): всё сохранённое
     * откладывается как есть, ничего не удаляется, ключ создаётся заново.
     * Туннель — остановить: его конфигурация из прежнего состояния.
     */
    private fun confirmStorageReset() {
        Ui.secure(
            AlertDialog.Builder(this)
                .setTitle(R.string.storage_reset_title)
                .setMessage(R.string.storage_reset_text)
                .setPositiveButton(R.string.storage_reset_confirm) { _, _ ->
                    val core = graph?.core ?: return@setPositiveButton
                    if (TunnelState.status.value.busy) disconnect()
                    scope.launch {
                        when (val r = withContext(Dispatchers.IO) { core.resetStorage() }) {
                            is Outcome.Success -> {
                                toast(getString(R.string.storage_reset_done))
                                changed()
                            }
                            is Outcome.Failure -> problem(getString(R.string.storage_reset_failed), r.errors.first())
                        }
                    }
                }
                .setNegativeButton(android.R.string.cancel, null)
                .show(),
        )
    }

    override fun connect() {
        askNotifications()
        val consent = VpnService.prepare(this)
        if (consent != null) {
            @Suppress("DEPRECATION") // Activity Result API есть только в AndroidX, а его нет (D-34)
            startActivityForResult(consent, REQUEST_VPN)
        } else {
            DPpassVpnService.start(this)
        }
    }

    override fun disconnect() {
        DPpassVpnService.stop(this)
    }

    override fun reconnectIfBusy() {
        if (!TunnelState.status.value.busy) return
        DPpassVpnService.reconnect(this)
        toast(getString(R.string.reconnecting))
    }

    override fun importText(text: String) = ImportFlow.handle(this, text)

    override fun pickFile() {
        val intent = Intent(Intent.ACTION_OPEN_DOCUMENT)
            .addCategory(Intent.CATEGORY_OPENABLE)
            .setType("*/*")
            .putExtra(Intent.EXTRA_MIME_TYPES, arrayOf("text/plain", "application/json", "application/octet-stream"))
        try {
            @Suppress("DEPRECATION") // Activity Result API есть только в AndroidX, а его нет (D-34)
            startActivityForResult(intent, REQUEST_FILE)
        } catch (e: android.content.ActivityNotFoundException) {
            toast(getString(R.string.no_system_screen))
        }
    }

    override fun pickQrImage() {
        val intent = Intent(Intent.ACTION_OPEN_DOCUMENT).addCategory(Intent.CATEGORY_OPENABLE).setType("image/*")
        try {
            @Suppress("DEPRECATION") // Activity Result API есть только в AndroidX, а его нет (D-34)
            startActivityForResult(intent, REQUEST_QR)
        } catch (e: android.content.ActivityNotFoundException) {
            toast(getString(R.string.no_system_screen))
        }
    }

    override fun saveDocument(name: String, text: String) {
        val intent = Intent(Intent.ACTION_CREATE_DOCUMENT)
            .addCategory(Intent.CATEGORY_OPENABLE)
            .setType("application/json")
            .putExtra(Intent.EXTRA_TITLE, name)
        try {
            pendingExport = text
            @Suppress("DEPRECATION") // Activity Result API есть только в AndroidX, а его нет (D-34)
            startActivityForResult(intent, REQUEST_EXPORT)
        } catch (e: android.content.ActivityNotFoundException) {
            pendingExport = null
            toast(getString(R.string.no_system_screen))
        }
    }

    /** Запись экспорта в выбранный файл — в фоне; документ после неё забыт. */
    private fun writeExport(uri: Uri) {
        val text = pendingExport ?: return toast(getString(R.string.export_failed))
        pendingExport = null
        scope.launch {
            val ok = withContext(Dispatchers.IO) {
                try {
                    contentResolver.openOutputStream(uri, "wt")?.use { it.write(text.toByteArray(Charsets.UTF_8)) } != null
                } catch (e: IOException) {
                    false
                } catch (e: SecurityException) {
                    false
                }
            }
            toast(getString(if (ok) R.string.export_done else R.string.export_failed))
        }
    }

    /** QR с картинки (D-65): чтение и распознавание — в фоне; текст — тем же путём, что буфер обмена. */
    private fun readQr(uri: Uri) {
        scope.launch {
            when (val r = withContext(Dispatchers.IO) { QrPicture.read(contentResolver, uri) }) {
                is Outcome.Success -> deliver(r.value)
                is Outcome.Failure -> problem(getString(R.string.import_qr_failed), r.errors.first())
            }
        }
    }

    /** Файл импорта — в фоне, не больше [ImportFlow.MAX_FILE_BYTES]: дальше разбор всё равно откажет. */
    private fun readFile(uri: Uri) {
        scope.launch {
            val text = withContext(Dispatchers.IO) {
                try {
                    contentResolver.openInputStream(uri)?.use { input ->
                        val bytes = input.readNBytesCompat(ImportFlow.MAX_FILE_BYTES + 1)
                        if (bytes.size > ImportFlow.MAX_FILE_BYTES) null else String(bytes, Charsets.UTF_8)
                    }
                } catch (e: IOException) {
                    null
                } catch (e: SecurityException) {
                    null
                }
            }
            if (text == null) toast(getString(R.string.import_file_failed)) else importText(text)
        }
    }

    private fun java.io.InputStream.readNBytesCompat(limit: Int): ByteArray {
        val out = java.io.ByteArrayOutputStream()
        val buf = ByteArray(16 * 1024)
        while (out.size() < limit) {
            val n = read(buf, 0, minOf(buf.size, limit - out.size()))
            if (n < 0) break
            out.write(buf, 0, n)
        }
        return out.toByteArray()
    }

    /** Android 13+: без разрешения уведомление туннеля не видно; туннель работает и без него. */
    private fun askNotifications() {
        if (askedNotifications || Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU) return
        if (checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) == PackageManager.PERMISSION_GRANTED) return
        askedNotifications = true
        requestPermissions(arrayOf(Manifest.permission.POST_NOTIFICATIONS), REQUEST_NOTIFICATIONS)
    }

    override fun onRequestPermissionsResult(requestCode: Int, permissions: Array<out String>, grantResults: IntArray) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults)
        if (requestCode == REQUEST_NOTIFICATIONS && grantResults.firstOrNull() == PackageManager.PERMISSION_DENIED) {
            toast(getString(R.string.notification_permission_note))
        }
    }

    @Deprecated("Activity Result API есть только в AndroidX, а его нет (D-34)")
    @Suppress("DEPRECATION")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        when {
            requestCode == REQUEST_VPN && resultCode == RESULT_OK -> DPpassVpnService.start(this)
            requestCode == REQUEST_VPN -> vpnConsentRefused()
            requestCode == REQUEST_FILE && resultCode == RESULT_OK -> data?.data?.let(::readFile)
            requestCode == REQUEST_QR && resultCode == RESULT_OK -> data?.data?.let(::readQr)
            requestCode == REQUEST_EXPORT && resultCode == RESULT_OK -> data?.data?.let(::writeExport)
            requestCode == REQUEST_EXPORT -> pendingExport = null
        }
    }

    /**
     * Согласия на VPN нет: пользователь отказал, или Android закрыл запрос
     * сам, ничего не показав, — так он делает, когда «Постоянный VPN»
     * включён у другого приложения (в том числе у сборки DPpass с другим
     * пакетом, D-49). Туннель не поднимается — с причиной, а не молча (D-22).
     */
    private fun vpnConsentRefused() {
        val reason = Diagnostic.error(
            DiagCode.TUN_ESTABLISH_FAILED,
            "Android не дал согласия на VPN. Если «Постоянный VPN» включён у другого приложения, " +
                "Android закрывает запрос сам: выключите его в настройках Android → Сеть → VPN.",
        )
        DeviceLog.log.diagnostic(reason)
        problem(getString(R.string.status_failed), reason)
    }

    override fun onResume() {
        super.onResume()
        (stack.lastOrNull() ?: tabs[tab]).onShown()
        changed()
    }

    override fun onPause() {
        (stack.lastOrNull() ?: tabs[tab]).onHidden()
        super.onPause()
    }

    override fun onStop() {
        super.onStop()
        // Интерфейс ушёл с экрана — отмечаем в журнале; наружу ничего не копируется (D-47).
        // Поворот экрана — не уход.
        if (!isChangingConfigurations) DeviceLog.onWorkFinished(this, "activity_stop")
    }

    override fun onDestroy() {
        scope.cancel()
        super.onDestroy()
    }

    private companion object {
        const val REQUEST_VPN = 1
        const val REQUEST_NOTIFICATIONS = 2
        const val REQUEST_FILE = 3
        const val REQUEST_QR = 4
        const val REQUEST_EXPORT = 5
        const val TRANSITION_MILLIS = 180L
    }
}
