package com.dpsmpx.dppass.connection

import com.dpsmpx.dppass.core.ProfileId
import com.dpsmpx.dppass.diagnostics.DiagCode
import com.dpsmpx.dppass.diagnostics.Diagnostic

/**
 * Сервер не принял разбитый ClientHello (D-69, к D-68): та же попытка — без
 * разбиения, и сервер запоминается. 19 октября 2026 на телефоне автора
 * входной узел CDN, получив ClientHello по нескольким записям TLS, отдал
 * сертификат «ни для какого имени»: он ищет имя только в первой записи.
 *
 * Повтор — только при отказе на уровне TLS или REALITY: там виновато
 * начало соединения. Отказ TCP (сброс, «соединение отвергнуто») случается
 * до ClientHello, а тайм-аут не говорит, при чём тут разбиение, — повтор
 * лишь удвоил бы ожидание.
 */
object SplitFallback {
    /**
     * Отказ похож на неразобранный ClientHello: через сервер не прошло ни
     * байта, и где-то в цепочке причин — ошибка TLS, сертификата или REALITY.
     * Текст ядра лежит в сводке ошибки причины (`ErrorSummary`, так пишет
     * проба здоровья `XrayHealth`), а не в сообщении: 19 октября 2026 на
     * телефоне повтор из-за этого не сработал.
     *
     * `TLS_HANDSHAKE_FAILED` пробы — TLS с DNS-сервером уже через сервер
     * профиля: соединение с сервером было, разбиение ни при чём.
     */
    fun rejectedBy(reason: Diagnostic): Boolean =
        reason.code == DiagCode.ENDPOINT_UNREACHABLE &&
            chain(reason).any { d -> MARKER.containsMatchIn(d.message) || d.error?.message?.let(MARKER::containsMatchIn) == true }

    private fun chain(d: Diagnostic): Sequence<Diagnostic> = sequenceOf(d) + d.causes.asSequence().flatMap { chain(it) }

    // Ошибки рукопожатия в Go и Xray: «tls: failed to verify certificate»,
    // «remote error: tls: handshake failure», «x509: certificate is not
    // valid…», «REALITY: processed invalid connection». Путь пакета Xray
    // («transport/internet/tls: …») — не отказ рукопожатия: у ECH и
    // настроек свои ошибки, а тайм-аут и сброс TCP приходят без этих слов.
    private val MARKER = Regex("""(?<![/\w])(tls|x509|REALITY): """)
}

/**
 * Серверы, не принявшие разбиение (D-69): к ним — без него, пока работает
 * процесс. Только в памяти: сервер могут перенастроить, а признак не
 * должен держаться вечно; после перезапуска — новая проба с разбиением.
 */
class SplitMemory {
    private val rejected = HashSet<ProfileId>()

    @Synchronized
    fun rejected(id: ProfileId): Boolean = id in rejected

    @Synchronized
    fun reject(id: ProfileId) {
        rejected += id
    }
}
