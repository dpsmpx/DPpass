package com.dpsmpx.dppass.connection

import com.dpsmpx.dppass.config.ServerProfile
import com.dpsmpx.dppass.config.TransportClass
import com.dpsmpx.dppass.config.transportClass
import com.dpsmpx.dppass.diagnostics.DiagCode
import com.dpsmpx.dppass.diagnostics.Outcome
import com.dpsmpx.dppass.engine.EngineSession
import com.dpsmpx.dppass.network.ProbeOutcome
import com.dpsmpx.dppass.network.simulation.PathClass
import com.dpsmpx.dppass.network.simulation.SimulatedNetwork

/**
 * Здоровье по модели сети — для тестов и `cli`. Тестовая фикстура
 * `connection`: в APK не попадает (`check_apk.py`).
 */
class SimulatedHealthChecker(private val network: SimulatedNetwork) : HealthChecker {
    override suspend fun check(session: EngineSession, profile: ServerProfile): Outcome<Unit> {
        val path = when (profile.transportClass) {
            TransportClass.TCP_STREAM -> PathClass.TCP_STREAM
            TransportClass.HTTP_CDN -> PathClass.HTTP_CDN
            TransportClass.UDP_QUIC -> PathClass.UDP_QUIC
            // Модель описывает сеть оператора; до устройства раздачи — своя сеть (D-55).
            TransportClass.LOCAL_RELAY -> return Outcome.Success(Unit)
        }
        return when (network.candidatePath(path, profile.endpoint.toString(), profile.hints.reachableUnderAllowlist)) {
            ProbeOutcome.SUCCESS -> Outcome.Success(Unit)
            ProbeOutcome.STALLED -> Outcome.failure(DiagCode.PAYLOAD_STALLED, "соединение установлено, но данные не идут")
            ProbeOutcome.RESET -> Outcome.failure(DiagCode.TLS_HANDSHAKE_FAILED, "соединение сброшено при рукопожатии")
            else -> Outcome.failure(DiagCode.ENDPOINT_UNREACHABLE, "сервер недоступен из этой сети")
        }
    }
}
