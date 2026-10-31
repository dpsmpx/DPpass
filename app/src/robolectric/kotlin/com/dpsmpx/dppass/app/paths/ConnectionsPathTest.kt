package com.dpsmpx.dppass.app.paths

import android.app.Activity
import com.dpsmpx.dppass.R
import com.dpsmpx.dppass.app.DPpassVpnService
import com.dpsmpx.dppass.app.TunnelState
import com.dpsmpx.dppass.app.TunnelStatus
import com.dpsmpx.dppass.app.device.expect
import com.dpsmpx.dppass.app.ui.ConnectionsScreen
import com.dpsmpx.dppass.app.ui.GridTable
import com.dpsmpx.dppass.app.ui.PowerButton
import com.dpsmpx.dppass.connection.ConnColumn
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.Robolectric
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.Shadows.shadowOf
import org.robolectric.annotation.Config

/**
 * Ключевой путь анализатора соединений (D-106): с «Подключения» — экран
 * «Соединения»; выключен — ни учёта в ядре, ни строк; переключатель
 * включает учёт в настоящем мосте Xray, «Сохранять уникальные соединения»
 * — журнал. Подключение без VPN (сервер синтетический, TEST-NET) — проба
 * здоровья DPpass идёт через исходящий `proxy` и видна в таблице как своё
 * соединение DPpass через сервер; журнал её записал; сортировка по
 * заголовку; «Очистить журнал подключений» с подтверждением стирает журнал;
 * выключение — учёт в ядре выключен.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [36])
class ConnectionsPathTest {
    @Test
    fun analyzerShowsCoreConnectionsAndKeepsTheJournal() {
        Act().use { act ->
            val c = act.context
            val a = act.launch()
            act.seed(a, LINK)
            val g = act.graph(a)
            val analyzer = g.core.analyzer
            act.tap(a, c.getString(R.string.tab_connect))
            act.waitFor(a, c.getString(R.string.conn_entry_off))
            act.tap(a, c.getString(R.string.conn_title))
            act.waitFor(a, c.getString(R.string.conn_off_hint))
            expect(g.engine.connections()?.enabled == false) { "анализатор выключен, а учёт в ядре идёт" }

            act.tap(a, c.getString(R.string.conn_switch))
            act.d.waitUntil("учёт в ядре включён") { analyzer.settings().enabled && g.engine.connections()?.enabled == true }
            act.tap(a, c.getString(R.string.conn_tab_journal))
            act.waitFor(a, c.getString(R.string.conn_keep))
            act.tap(a, c.getString(R.string.conn_keep))
            act.d.waitUntil("журнал уникальных включён") { analyzer.settings().keepUnique }
            act.tap(a, c.getString(R.string.action_back))

            // Без VPN: ядро поднимается с локальным прокси и проверяет здоровье через сервер.
            act.waitFor(a, c.getString(R.string.source_subscription, "Synthetic"))
            act.tap(a, c.getString(R.string.action_connect), PowerButton::class.java)
            val consent = act.d.main { shadowOf(a).nextStartedActivityForResult }
            expect(consent != null) { "«Подключить» не спросило согласия на VPN" }
            act.d.main { shadowOf(a).receiveResult(consent!!.intent, Activity.RESULT_CANCELED, null) }
            act.waitFor(a, c.getString(R.string.local_proxy_offer))
            act.tap(a, c.getString(R.string.local_proxy_offer))
            act.d.waitUntil("режим без VPN включён") { g.core.localProxy.enabled() }
            val intent = act.d.main { shadowOf(RuntimeEnvironment.getApplication()).nextStartedService }
            expect(intent?.component?.className == DPpassVpnService::class.java.name) { "сервис не запущен: $intent" }
            val service = act.d.main { Robolectric.buildService(DPpassVpnService::class.java, intent).create().startCommand(0, 1) }
            act.d.waitUntil("попытка закончилась", 60_000) { TunnelState.status.value is TunnelStatus.Failed }
            act.d.main { service.destroy() }

            // Таблица: проба DPpass — своё соединение, через сервер, закончилось.
            act.waitFor(a, c.getString(R.string.conn_entry_on))
            act.tap(a, c.getString(R.string.conn_title))
            act.waitFor(a, c.getString(R.string.conn_switch))
            val table = act.view(a, GridTable::class.java)
            expect(table != null) { "нет таблицы на экране" }
            fun cell(row: Int, col: ConnColumn): String = act.d.main { table!!.model!!.text(row, ConnectionsScreen.LIVE.indexOf(col)) }
            fun rows(): Int = act.d.main { table!!.model?.rows ?: 0 }
            act.d.waitUntil("строка пробы в таблице", 15_000) { rows() > 0 }
            val proxy = (0 until rows()).firstOrNull { cell(it, ConnColumn.ROUTE) == c.getString(R.string.conn_route_proxy) }
            expect(proxy != null) { "нет соединения через сервер: ${(0 until rows()).map { cell(it, ConnColumn.HOST) + " " + cell(it, ConnColumn.ROUTE) }}" }
            val inbound = cell(proxy!!, ConnColumn.INBOUND)
            expect(inbound == c.getString(R.string.conn_in_self)) { "проба DPpass — не своё соединение: $inbound" }
            expect(cell(proxy, ConnColumn.STATE) != c.getString(R.string.conn_state_open)) { "проба после отказа всё ещё открыта" }

            // Сортировка нажатием на заголовок: адрес — по алфавиту, снова — обратно.
            val host = ConnectionsScreen.LIVE.indexOf(ConnColumn.HOST)
            act.d.main { table!!.onHeader!!(host) }
            act.d.idle()
            expect(act.d.main { table!!.model!!.sortColumn == host && !table.model!!.sortDescending }) { "заголовок «Адрес» не отсортировал по алфавиту" }
            act.d.main { table!!.onHeader!!(host) }
            act.d.idle()
            expect(act.d.main { table!!.model!!.sortDescending }) { "второе нажатие не перевернуло порядок" }

            // Журнал: соединение пробы записано; очистка — с подтверждением.
            act.d.waitUntil("журнал записал соединение", 15_000) { analyzer.unique().isNotEmpty() }
            act.tap(a, c.getString(R.string.conn_tab_journal))
            act.waitFor(a, c.getString(R.string.conn_journal_count, analyzer.unique().size))
            act.tap(a, c.getString(R.string.conn_clear))
            act.waitFor(a, c.getString(R.string.conn_clear_confirm, analyzer.unique().size))
            act.tap(a, c.getString(android.R.string.ok))
            act.waitFor(a, c.getString(R.string.conn_journal_empty))
            expect(analyzer.unique().isEmpty()) { "журнал не очищен" }

            act.tap(a, c.getString(R.string.conn_switch))
            act.d.waitUntil("учёт в ядре выключен") { !analyzer.settings().enabled && g.engine.connections()?.enabled == false }
        }
    }

    private companion object {
        const val LINK = "vless://00000000-0000-4000-8000-000000000032@203.0.113.32:443?security=tls&sni=b.example.com#Beta"
    }
}
