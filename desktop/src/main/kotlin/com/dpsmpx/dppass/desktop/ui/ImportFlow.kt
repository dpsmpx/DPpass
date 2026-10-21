package com.dpsmpx.dppass.desktop.ui

import com.dpsmpx.dppass.connection.ActivationResult
import com.dpsmpx.dppass.connection.ImportClassifier
import com.dpsmpx.dppass.connection.ImportKind
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
            ImportKind.OwnDocument -> if (confirm("Это документ DPpass: своя конфигурация с маршрутизацией. Применить его?")) activate(text)
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
            is ImportKind.Relay -> info("Вход устройства раздачи (D-55) в DPpass для Linux пока не поддерживается.")
            is ImportKind.Unrecognized -> {
                val why = kind.reason?.let { "\n\n" + it.message }.orEmpty()
                info("Не распознано: ни документ DPpass, ни адрес подписки, ни ссылки.$why")
            }
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
    }
}
