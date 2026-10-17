package com.dpsmpx.dppass.app

import android.app.job.JobInfo
import android.app.job.JobParameters
import android.app.job.JobScheduler
import android.app.job.JobService
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import com.dpsmpx.dppass.diagnostics.Outcome
import com.dpsmpx.dppass.diagnostics.Safe
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch

/**
 * Автообновление подписок (D-39). `JobScheduler` будит раз в час при
 * сети; пора ли обновлять — решает ядро (`SubscriptionService.refreshDue`,
 * `UpdateSchedule`). Обновляется только применённая подписка.
 *
 * Туннель поднят: новые серверы активированы (D-07), переподключение —
 * только если подключённого сервера больше нет или он изменился.
 */
class SubscriptionJobService : JobService() {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private var running: Job? = null

    override fun onStartJob(params: JobParameters): Boolean {
        running = scope.launch {
            try {
                val graph = AppGraph.graph(this@SubscriptionJobService)
                val core = graph.core
                if (core.activation.state.activeConfig == null) core.restore()
                val r = core.subscriptions.refreshDue(graph.fetcher, graph.appVersion)
                when (r) {
                    null -> Unit
                    is Outcome.Failure -> r.errors.forEach(core.log::diagnostic)
                    is Outcome.Success -> {
                        val run = r.value
                        core.log.info("subscription_auto_update", "applied" to run.applied, "update" to Safe(run.update::class.simpleName ?: "?"))
                        val connected = (TunnelState.status.value as? TunnelStatus.Connected)?.profileId
                        // Через устройство раздачи (D-55) туннель от серверов подписки не зависит.
                        if (AppPrefs(this@SubscriptionJobService).selectedRelay == null && run.needsReconnect(connected)) {
                            // Сервис туннеля уже в foreground: обычный запуск из фона ему разрешён.
                            startService(Intent(this@SubscriptionJobService, DPpassVpnService::class.java).setAction(DPpassVpnService.ACTION_RECONNECT))
                        }
                    }
                }
            } finally {
                jobFinished(params, false)
            }
        }
        return true
    }

    override fun onStopJob(params: JobParameters): Boolean {
        running?.cancel()
        // Срок ещё не вышел — следующая попытка через час сама.
        return false
    }

    companion object {
        private const val JOB_ID = 1001
        private const val PERIOD_MILLIS = 60 * 60_000L

        /** Раз в час при сети; ставится при каждом запуске процесса (задача не переживает перезагрузку, D-39). */
        fun schedule(context: Context) {
            val js = context.getSystemService(JobScheduler::class.java) ?: return
            if (js.getPendingJob(JOB_ID) != null) return
            val info = JobInfo.Builder(JOB_ID, ComponentName(context, SubscriptionJobService::class.java))
                .setPeriodic(PERIOD_MILLIS)
                .setRequiredNetworkType(JobInfo.NETWORK_TYPE_ANY)
                .setPersisted(false)
                .build()
            js.schedule(info)
        }
    }
}
