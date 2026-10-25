package com.dpsmpx.dppass.app.paths

import android.app.Activity
import android.content.ClipData
import android.content.ClipboardManager
import android.view.View
import android.view.ViewGroup
import android.widget.EditText
import android.widget.TextView
import androidx.test.platform.app.InstrumentationRegistry
import com.dpsmpx.dppass.app.DeviceLog
import com.dpsmpx.dppass.app.device.Device
import com.dpsmpx.dppass.app.device.expect
import com.dpsmpx.dppass.app.screens.JvmHands
import com.dpsmpx.dppass.app.ui.Host
import com.dpsmpx.dppass.diagnostics.DiagCode
import com.dpsmpx.dppass.diagnostics.Outcome
import com.dpsmpx.dppass.subscriptions.FetchedPayload
import com.dpsmpx.dppass.subscriptions.SubscriptionFetcher
import kotlinx.coroutines.runBlocking
import org.robolectric.shadows.ShadowDialog
import org.robolectric.shadows.ShadowToast

/**
 * Руки тестов ключевых путей (D-90): нажать, ввести, вставить в буфер —
 * только на JVM, в песочнице Robolectric с пустыми данными приложения.
 * Глаза и ожидание — те же, что у тестов телефона ([Device]); действуют
 * они в верхнем окне: в листе или окне вопроса, если оно открыто, иначе —
 * в экране.
 */
class Act : AutoCloseable {
    init {
        SandboxKeyStore.install()
    }

    val d = Device(InstrumentationRegistry.getInstrumentation(), JvmHands())
    val context = d.context

    /**
     * Экран с собранным графом приложения: до этого экраны пустые. Ядро —
     * настоящее: без него конфигурация не прошла бы проверку ядром, и путь
     * кончился бы не там, где на телефоне.
     */
    fun launch(): Activity = d.launch().also { a ->
        d.waitUntil("граф приложения собран") { (a as Host).graph != null }
        expect(DeviceLog.memory.snapshot().any { it.event == "engine_loaded" }) {
            "ядра Xray на JVM нет: python3 tools/xray/native.py host и -Pdppass.xray.lib=build/xray/host/libdppassxray.so (D-90)"
        }
    }

    fun graph(a: Activity) = checkNotNull((a as Host).graph)

    /** Верхнее окно: открытый лист или вопрос, иначе экран. */
    fun top(a: Activity): View = d.main { ShadowDialog.getLatestDialog()?.takeIf { it.isShowing }?.window?.decorView ?: a.window.decorView }

    /** Видимые тексты верхнего окна — для сообщений о провале и проверок «есть на экране». */
    fun texts(a: Activity): List<String> = d.main { buildList { collect(top(a), this) } }

    fun shows(a: Activity, text: String): Boolean = texts(a).any { text in it }

    /** Есть ли в верхнем окне вид с подписью [label] — текстом или описанием для TalkBack. */
    fun labelled(a: Activity, label: String): Boolean = d.main { find(top(a)) { it.label() == label } != null }

    /** Ждать [text] в верхнем окне; не дождался — провал с тем, что видно в этот момент. */
    fun waitFor(a: Activity, text: String, timeoutMillis: Long = 10_000) = try {
        d.waitUntil("«$text» на экране", timeoutMillis) { shows(a, text) }
    } catch (e: AssertionError) {
        throw AssertionError("${e.message}; видно: ${texts(a).take(MAX_SHOWN)}", e)
    }

    /**
     * Нажать вид с подписью [label] (текст или описание): его или ближайшего
     * нажимаемого родителя. [kind] — когда подпись не одна: у вкладки
     * «Подключение» и у кнопки питания она одинаковая.
     */
    fun tap(a: Activity, label: String, kind: Class<out View> = View::class.java) {
        val v = d.main { find(top(a)) { kind.isInstance(it) && it.label() == label } }
        checkNotNull(v) { "нет «$label» на экране; видно: ${texts(a).take(MAX_SHOWN)}" }
        d.main {
            var target: View = v
            while (!target.isClickable) target = target.parent as? View ?: error("у «$label» нет нажимаемого родителя")
            target.performClick()
        }
        d.idle()
    }

    /** Ввести [text] в поле с подсказкой [hint] верхнего окна. */
    fun type(a: Activity, hint: String, text: String) {
        val field = d.main { find(top(a)) { it is EditText && it.hint?.toString() == hint } as? EditText }
        checkNotNull(field) { "нет поля «$hint»" }
        d.main { field.setText(text) }
    }

    /**
     * Свои серверы из [links] — сразу в ядро, мимо экранов: путь, который
     * проверяет тест, начинается после импорта (импорт — `ImportPathTest`).
     */
    fun seed(a: Activity, links: String, name: String = "Synthetic") {
        val g = graph(a)
        val sub = g.core.subscriptions.addInline(links, name)
        check(sub is Outcome.Success) { "свои серверы не добавлены: $sub" }
        val run = runBlocking { g.core.subscriptions.refresh(sub.value.id, NO_NETWORK, g.appVersion) }
        check(run.valueOrNull()?.applied == true) { "свои серверы не применены: $run" }
        d.main { (a as Host).changed() }
        d.idle()
    }

    /**
     * Подписка по адресу [url] с ответом поставщика [body] и [headers] — в
     * ядро, мимо сети: ответ отдаёт тест (загрузка по HTTPS проверяется на
     * хосте, `HttpsSubscriptionFetcherTest`).
     */
    fun seedSubscription(a: Activity, url: String, body: String, headers: Map<String, String>) {
        val g = graph(a)
        val sub = g.core.subscriptions.add(url, null)
        check(sub is Outcome.Success) { "подписка не добавлена: $sub" }
        val provider = SubscriptionFetcher { _, _ -> Outcome.Success(FetchedPayload(body.toByteArray(), headers, System.currentTimeMillis())) }
        val run = runBlocking { g.core.subscriptions.refresh(sub.value.id, provider, g.appVersion) }
        check(run.valueOrNull()?.applied == true) { "подписка не применена: $run" }
        d.main { (a as Host).changed() }
        d.idle()
    }

    /** Цвет текста первого вида верхнего окна, где есть [part]; нет такого — null. */
    fun colorOf(a: Activity, part: String): Int? = d.main { (find(top(a)) { (it as? TextView)?.text?.contains(part) == true } as? TextView)?.currentTextColor }

    fun clipboard(text: String) = d.main {
        context.getSystemService(ClipboardManager::class.java).setPrimaryClip(ClipData.newPlainText("", text))
    }

    fun toast(): String? = d.main { ShadowToast.getTextOfLatestToast() }

    override fun close() = d.close()

    private fun View.label(): String? = contentDescription?.toString() ?: (this as? TextView)?.text?.toString()

    private fun find(v: View, test: (View) -> Boolean): View? {
        if (!v.isShown) return null
        if (test(v)) return v
        if (v is ViewGroup) for (i in 0 until v.childCount) find(v.getChildAt(i), test)?.let { return it }
        return null
    }

    private fun collect(v: View, out: MutableList<String>) {
        if (!v.isShown) return
        (v as? TextView)?.text?.toString()?.takeIf { it.isNotBlank() }?.let(out::add)
        if (v is ViewGroup) for (i in 0 until v.childCount) collect(v.getChildAt(i), out)
    }

    private companion object {
        const val MAX_SHOWN = 30

        /** Своим серверам сеть не нужна (D-42); тестам путей её нет (`docs/TESTING.md`, «Без сети»). */
        val NO_NETWORK = SubscriptionFetcher { _, _ -> Outcome.failure(DiagCode.SUBSCRIPTION_FETCH_FAILED, "сети в тестах путей нет (D-90)") }
    }
}
