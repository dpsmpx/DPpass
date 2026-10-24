package com.dpsmpx.dppass.desktop

import com.dpsmpx.dppass.connection.Pairing
import com.dpsmpx.dppass.connection.RelayDevice
import com.dpsmpx.dppass.connection.RelayDraft
import com.dpsmpx.dppass.connection.RelayService
import com.dpsmpx.dppass.diagnostics.DiagCode
import com.dpsmpx.dppass.diagnostics.Diagnostic
import com.dpsmpx.dppass.diagnostics.Logger
import com.dpsmpx.dppass.diagnostics.Outcome
import java.io.IOException
import java.security.SecureRandom

/**
 * Сопряжение ПК с раздающим телефоном (D-56, D-85): ПК — гость. Найти
 * телефон, который ждёт сопряжения на шлюзе сети ПК, сверить код на обоих
 * экранах ([confirm] — ответ пользователя ПК) и добавить выданный вход в
 * доверенные устройства. Адрес не запоминается — шлюз сети, как у ссылки.
 * Блокирует поток: вызывать на потоке ввода-вывода.
 */
object RelayPairing {
    const val DEFAULT_NAME: String = "Устройство раздачи"

    suspend fun pair(
        networks: LinuxRelayNetworks,
        relays: RelayService,
        log: Logger,
        random: SecureRandom = SecureRandom(),
        confirm: suspend (String) -> Boolean,
    ): Outcome<RelayDevice> {
        val socket = networks.pairingHost() ?: return Outcome.failure(
            DiagCode.PAIRING_NOT_FOUND,
            "раздающий телефон не ждёт сопряжения: на нём «Раздача туннеля» → «Сопряжение с устройством», а ПК — " +
                "в его точке доступа, USB- или Bluetooth-модеме",
        )
        val r = try {
            socket.use { s -> Pairing.guest(s.getInputStream(), s.getOutputStream(), random, confirm) }
        } catch (e: IOException) {
            Outcome.failure(Diagnostic.fromThrowable(DiagCode.PAIRING_BROKEN, "соединение сопряжения прервано", e))
        }
        val offer = when (r) {
            is Outcome.Failure -> return r
            is Outcome.Success -> r.value
        }
        val name = offer.name.takeIf { RelayService.nameProblem(it) == null } ?: DEFAULT_NAME
        return relays.add(RelayDraft(name, "", offer.port, offer.user, offer.password)).also { if (it is Outcome.Success) log.info("relay_paired") }
    }
}
