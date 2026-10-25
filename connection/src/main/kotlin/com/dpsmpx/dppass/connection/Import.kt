package com.dpsmpx.dppass.connection

import com.dpsmpx.dppass.config.ConfigFormat
import com.dpsmpx.dppass.diagnostics.DiagCode
import com.dpsmpx.dppass.diagnostics.Diagnostic
import com.dpsmpx.dppass.diagnostics.Outcome
import com.dpsmpx.dppass.subscriptions.PayloadDecoder

/** Что пользователь принёс: буфер обмена, файл, «Поделиться» (D-42). */
sealed interface ImportKind {
    /** Пусто или одни пробелы. */
    data object Empty : ImportKind

    /** Документ DPpass — своя конфигурация с маршрутизацией (D-06). */
    data object OwnDocument : ImportKind

    /** Один адрес `https://…` — подписка. */
    data class SubscriptionUrl(val url: String) : ImportKind

    /**
     * Ссылки на серверы (`vless://` и др.) или их список в base64.
     * [usable] — сколько из [total] записей разобралось; [problems] —
     * почему остальные нет (без значений из ссылок).
     */
    data class Links(val usable: Int, val total: Int, val problems: List<Diagnostic>) : ImportKind

    /**
     * Вход раздачи другого DPpass (`socks5://…`, D-55): не сервер подписки, а
     * устройство — добавляется в список устройств раздачи, если пользователь
     * согласится.
     */
    data class Relay(val link: RelayLink) : ImportKind

    /**
     * Профиль маршрутизации Happ (D-93): JSON или `happ://routing/…`. Его
     * списки сайтов можно добавить в свои — после сводки, что берётся, а
     * что нет и почему.
     */
    data class HappRouting(val text: String) : ImportKind

    /** Не распознано: ни документ, ни адрес, ни ссылки. */
    data class Unrecognized(val reason: Diagnostic?) : ImportKind
}

/**
 * Распознавание принесённого текста (D-42). Ничего не сохраняет и не
 * активирует: только говорит, что это, — решает пользователь, увидев
 * сводку. Текст из «Поделиться» — данные чужого приложения (T13).
 */
object ImportClassifier {
    /** Больше документ DPpass всё равно не примет (`ConfigLimits.maxBytes`). */
    const val MAX_BYTES: Int = 1 shl 20

    fun classify(text: String): ImportKind {
        val t = text.removePrefix("\uFEFF").trim()
        if (t.isEmpty()) return ImportKind.Empty
        if (t.toByteArray(Charsets.UTF_8).size > MAX_BYTES) {
            return ImportKind.Unrecognized(Diagnostic.error(DiagCode.DOCUMENT_TOO_LARGE, "больше $MAX_BYTES байт — столько DPpass не примет"))
        }
        if (t.startsWith("{") && "\"${ConfigFormat.MARKER}\"" in t) return ImportKind.OwnDocument
        if (SubscriptionService.isSubscriptionUrl(t) && '\n' !in t) return ImportKind.SubscriptionUrl(t)
        if (t.startsWith("http://", ignoreCase = true) && '\n' !in t) {
            return ImportKind.Unrecognized(Diagnostic.error(DiagCode.SUBSCRIPTION_FETCH_FAILED, "подписка загружается только по https://"))
        }
        // Одна строка https://, но не адрес подписки (пробел, управляющий символ, длина):
        // причина — правило адреса, а не «схема https:// неизвестна» из разбора ссылок.
        if (t.startsWith("https://", ignoreCase = true) && '\n' !in t) {
            return ImportKind.Unrecognized(Diagnostic.error(DiagCode.SUBSCRIPTION_FETCH_FAILED, SubscriptionService.URL_RULE))
        }
        if (HappRouting.isEncrypted(t)) {
            return ImportKind.Unrecognized(
                Diagnostic.error(
                    DiagCode.SUBSCRIPTION_FORMAT_UNKNOWN,
                    "зашифрованная ссылка Happ прячет конфигурацию от вас самих — DPpass такие не открывает (D-11)",
                ),
            )
        }
        if (HappRouting.looksLike(t)) return ImportKind.HappRouting(t)
        if (t.startsWith("{")) return ImportKind.Unrecognized(null)
        if (RelayLink.looksLike(t)) {
            return when (val r = RelayLink.parse(t)) {
                is Outcome.Failure -> ImportKind.Unrecognized(r.errors.firstOrNull())
                is Outcome.Success -> ImportKind.Relay(r.value)
            }
        }
        return when (val d = PayloadDecoder.decode(t.toByteArray(Charsets.UTF_8), "import", MAX_ENTRIES)) {
            is Outcome.Failure -> ImportKind.Unrecognized(d.errors.firstOrNull())
            is Outcome.Success -> {
                val problems = d.diagnostics.filter { it.severity != com.dpsmpx.dppass.diagnostics.Severity.INFO }
                val total = d.value.profiles.size + problems.count { it.path?.startsWith("entry[") == true }
                if (d.value.profiles.isEmpty() && total == 0) ImportKind.Unrecognized(null) else ImportKind.Links(d.value.profiles.size, total, problems)
            }
        }
    }

    private const val MAX_ENTRIES = 1000
}
