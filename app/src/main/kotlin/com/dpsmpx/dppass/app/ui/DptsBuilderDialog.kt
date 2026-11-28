package com.dpsmpx.dppass.app.ui

import android.app.AlertDialog
import android.content.Context
import android.text.InputFilter
import android.text.InputType
import android.view.View
import android.widget.ArrayAdapter
import android.widget.CheckBox
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.Spinner
import android.widget.TextView
import com.dpsmpx.dppass.R
import com.dpsmpx.dppass.app.DptsBuilder

/** Offline authoring only. Insertion is separate from execution and learning. */
internal object DptsBuilderDialog {
    fun show(context: Context, insert: (String) -> Unit) {
        val modes = DptsBuilder.Mode.entries
        AlertDialog.Builder(context).setTitle(R.string.dpts_builder_protocol)
            .setItems(modes.map { it.label }.toTypedArray()) { _, index ->
                showOptions(context, modes[index], insert)
            }.setNegativeButton(android.R.string.cancel, null).show()
    }

    private fun showOptions(context: Context, mode: DptsBuilder.Mode, insert: (String) -> Unit) {
        val body = Ui.column(context, 8).apply {
            val pad = Ui.dp(context, 16)
            setPadding(pad, pad, pad, pad)
        }
        fun label(id: Int) {
            body.addView(Ui.text(context, R.style.Text_DPpass_Body, context.getString(id)))
        }
        fun field(id: Int, initial: String, max: Int, type: Int): EditText {
            label(id)
            return EditText(context).apply {
                inputType = type
                isSingleLine = true
                filters = arrayOf(InputFilter.LengthFilter(max))
                setText(initial)
                body.addView(this, Ui.matchWidth())
            }
        }
        fun choices(id: Int, options: List<Int>, default: Int): Spinner {
            label(id)
            return Spinner(context).apply {
                adapter = ArrayAdapter(context, android.R.layout.simple_spinner_item, options.map { it.toString() }).apply {
                    setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item)
                }
                setSelection(options.indexOf(default).coerceAtLeast(0))
                body.addView(this, Ui.matchWidth())
            }
        }
        val title = field(R.string.dpts_builder_name, "DPTS " + mode.label, 80, InputType.TYPE_CLASS_TEXT)
        val host = field(R.string.dpts_builder_host, "example.org", 253,
            InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_URI)
        val ipValues = (1..mode.maxIps).toList()
        val attemptsValues = (1..3).toList()
        val timeouts = listOf(1000, 2000, 3000, 5000, 8000, 12000)
        val ips = choices(R.string.dpts_builder_ips, ipValues, 2)
        val attempts = choices(R.string.dpts_builder_attempts, attemptsValues, 1)
        val timeout = choices(R.string.dpts_builder_timeout, timeouts, 5000)
        label(R.string.dpts_builder_methods)
        val methods = mode.methods().associateWith { method ->
            CheckBox(context).apply {
                text = method
                isChecked = method == "plain"
                body.addView(this, Ui.matchWidth())
            }
        }
        val observe = CheckBox(context).apply {
            text = context.getString(R.string.dpts_builder_observe)
            visibility = if (mode.https) View.VISIBLE else View.GONE
            body.addView(this, Ui.matchWidth())
        }
        val error = Ui.text(context, R.style.Text_DPpass_Secondary)
        body.addView(error, Ui.matchWidth())
        val scroll = ScrollView(context).apply { addView(body) }
        val dialog = AlertDialog.Builder(context).setTitle(mode.label).setView(scroll)
            .setNegativeButton(android.R.string.cancel, null)
            .setPositiveButton(R.string.dpts_preview_plan, null).create()
        dialog.setOnShowListener {
            dialog.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener {
                val draft = try {
                    DptsBuilder.create(title.text.toString().trim(), host.text.toString().trim(), mode,
                        methods.filterValues { it.isChecked }.keys, ipValues[ips.selectedItemPosition],
                        attemptsValues[attempts.selectedItemPosition], timeouts[timeout.selectedItemPosition],
                        observe.isChecked)
                } catch (e: IllegalArgumentException) {
                    error.text = e.message.orEmpty()
                    return@setOnClickListener
                }
                AlertDialog.Builder(context).setTitle(R.string.dpts_preview_plan)
                    .setMessage(context.getString(R.string.dpts_builder_summary, draft.plan.probes.size,
                        draft.plan.budgetMs / 1000) + "\n\n" + draft.source)
                    .setNegativeButton(android.R.string.cancel, null)
                    .setPositiveButton(R.string.dpts_builder_insert) { _, _ ->
                        dialog.dismiss()
                        insert(draft.source)
                    }.show()
            }
        }
        dialog.show()
    }
}
