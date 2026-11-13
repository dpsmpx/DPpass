package com.dpsmpx.dppass.desktop.ui

import com.dpsmpx.dppass.connection.ActivationResult
import com.dpsmpx.dppass.connection.ImportClassifier
import com.dpsmpx.dppass.connection.ImportKind
import com.dpsmpx.dppass.connection.RelayLink
import com.dpsmpx.dppass.desktop.DesktopGraph
import com.dpsmpx.dppass.diagnostics.Outcome
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.awt.Component
import java.awt.Toolkit
import java.awt.datatransfer.DataFlavor
import java.awt.datatransfer.UnsupportedFlavorException
import java.io.File
import java.io.IOException
import javax.swing.JFileChooser
import javax.swing.JOptionPane

/**
 * Импорт (D-42): текст из буфера обмена или файла — данные чужой программы
 * (T13). Сначала распознаётся, что это, и пользователь видит сводку; без
 * его «Да» ничего не сохраняется и не применяется.
 */
class ImportFlow(
    private val graph: DesktopGraph,
    private val scope: CoroutineScope,
    private val parent: () -> Component,
    private val subscriptions: SubscriptionsPanel,
    private val changed: () -> Unit,
    /** Устройство раздачи добавлено ссылкой (D-85): показать его в списке. */
    private val relaysChanged: () -> Unit,
    /** Политика сменилась (свои списки, D-93): туннель — переподключить, если поднят. */
    private val reconnect: () -> Unit = {},
) {
    fun fromClipboard() {
        val text = try {
            Toolkit.getDefaultToolkit().systemClipboard.getData(DataFlavor.stringFlavor) as? String
        } catch (_: UnsupportedFlavorException) {
            null
        } catch (_: IOException) {
            null
        } catch (_: IllegalStateException) {
            null
        }
        if (text.isNullOrBlank()) return info("В буфере обмена нет текста.")
        handle(text)
    }

    fun fromFile() {
        val chooser = JFileChooser()
        if (chooser.showOpenDialog(parent()) != JFileChooser.APPROVE_OPTION) return
        val f: File = chooser.selectedFile
        if (f.length() > ImportClassifier.MAX_BYTES) return info("Файл больше ${ImportClassifier.MAX_BYTES} байт — столько DPpass не примет.")
        val text = try {
            f.readText()
        } catch (e: IOException) {
            return info("Файл не прочитан: ${e.message}")
        }
        handle(text)
    }

    private fun handle(text: String) {
        when (val kind = ImportClassifier.classify(text)) {
            ImportKind.Empty -> info("Пусто — импортировать нечего.")
            ImportKind.OwnDocument -> confirmDocument(text)
            is ImportKind.SubscriptionUrl -> subscriptions.addByUrl(kind.url)
            is ImportKind.Links -> {
                val skipped = kind.problems.take(PROBLEMS_SHOWN).joinToString("\n") { "• " + it.message }
                val question = "Ссылки на серверы: разобралось ${kind.usable} из ${kind.total}." +
                    (if (skipped.isEmpty()) "" else "\n\nНе разобрались:\n$skipped") +
                    "\n\nДобавить их как «Свои серверы» и применить?"
                when {
                    kind.usable == 0 -> info(question.substringBefore("\n\nДобавить"))
                    confirm(question) -> addInline(text)
                }
            }
            is ImportKind.Relay -> addRelay(kind.link)
            is ImportKind.HappRouting -> when (val r = graph.core.parseHappRouting(text)) {
                is Outcome.Failure -> info("Профиль маршрутизации не взят:\n\n" + Widgets.describe(r.errors.first()))
                is Outcome.Success -> SiteListsDialog.confirmHapp(parent(), graph.core, scope, r.value) {
                    changed()
                    reconnect()
                }
            }
            is ImportKind.Unrecognized -> {
                val why = kind.reason?.let { "\n\n" + it.message }.orEmpty()
                info("Не распознано: ни документ DPpass, ни адрес подписки, ни ссылки.$why")
            }
        }
    }

    /** Предупреждения разбора показываются до согласия, а не теряются после активации (R-02). */
    private fun confirmDocument(text: String) {
        scope.launch(Edt) {
            val checked = withContext(Dispatchers.IO) { graph.core.load(text) }
            if (checked is Outcome.Failure) {
                info("Документ не принят:\n\n" + checked.errors.joinToString("\n\n") { Widgets.describe(it) })
                return@launch
            }
            val warnings = checked.diagnostics.filterNot { it.isError }.joinToString("\n\n") { Widgets.describe(it) }
            val question = "Это документ DPpass: своя конфигурация с маршрутизацией." +
                (if (warnings.isEmpty()) "" else "\n\n$warnings") + "\n\nПрименить его?"
            if (confirm(question)) activate(text)
        }
    }

    private fun activate(text: String) {
        scope.launch(Edt) {
            when (val r = withContext(Dispatchers.IO) { graph.core.importAndActivate(text) }) {
                is Outcome.Failure -> info("Документ не принят:\n\n" + r.errors.joinToString("\n\n") { Widgets.describe(it) })
                is Outcome.Success -> when (val a = r.value) {
                    is ActivationResult.Activated -> {
                        changed()
                        info("Документ применён: серверов — ${graph.core.activation.state.activeConfig?.profiles?.size ?: 0}.")
                    }
                    is ActivationResult.Rejected -> {
                        val why = a.diagnostics.joinToString("\n\n") { Widgets.describe(it) }
                        info("Документ не применён (шаг ${a.record.failedStep}):\n\n$why")
                    }
                }
            }
        }
    }

    private fun addInline(text: String) {
        val name = JOptionPane.showInputDialog(parent(), "Название списка серверов:", "Свои серверы") ?: return
        when (val r = graph.core.subscriptions.addInline(text, name)) {
            is Outcome.Failure -> info("Не добавлено:\n\n" + Widgets.describe(r.errors.first()))
            is Outcome.Success -> {
                subscriptions.reload()
                subscriptions.refresh(r.value.id, r.value.name)
            }
        }
    }

    /**
     * Вход устройства раздачи (D-55, D-85) — ссылка «Поделиться входом» с того
     * телефона: с согласия и под выбранным именем — в доверенные. Адрес
     * берётся из сети, через которую ПК к нему подключён, а не из ссылки.
     */
    private fun addRelay(link: RelayLink) {
        if (graph.relayNetworks == null) {
            return info("Это ссылка на вход устройства раздачи. Без библиотеки ядра DPpass сети ПК не узнать: ссылка не добавлена.")
        }
        val question = note(
            "Добавить раздачу туннеля другого телефона (порт ${link.port})? Адрес берётся из сети, через которую ПК к нему подключён.\n\nИмя:",
        )
        val name = JOptionPane.showInputDialog(parent(), question, link.draft(RELAY_NAME).name) ?: return
        when (val r = graph.core.relays.add(link.draft(RELAY_NAME).copy(name = name))) {
            is Outcome.Failure -> info("Не добавлено:\n\n" + Widgets.describe(r.errors.first()))
            is Outcome.Success -> {
                relaysChanged()
                info("Устройство «${r.value.name}» добавлено: выберите его на вкладке «Устройства раздачи».")
            }
        }
    }

    private fun confirm(question: String): Boolean =
        JOptionPane.showConfirmDialog(parent(), note(question), "Импорт", JOptionPane.YES_NO_OPTION, JOptionPane.QUESTION_MESSAGE) == JOptionPane.YES_OPTION

    private fun info(text: String) = JOptionPane.showMessageDialog(parent(), note(text), "Импорт", JOptionPane.INFORMATION_MESSAGE)

    private fun note(text: String) = Widgets.note().also {
        it.text = text
        it.columns = COLUMNS
    }

    private companion object {
        const val PROBLEMS_SHOWN = 5
        const val COLUMNS = 48
        const val RELAY_NAME = "Устройство раздачи"
    }
}
