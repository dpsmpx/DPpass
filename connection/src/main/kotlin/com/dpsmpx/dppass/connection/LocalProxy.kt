package com.dpsmpx.dppass.connection

import com.dpsmpx.dppass.core.Json
import com.dpsmpx.dppass.core.JsonBool
import com.dpsmpx.dppass.core.JsonNumber
import com.dpsmpx.dppass.core.JsonObject
import com.dpsmpx.dppass.core.JsonParseException
import com.dpsmpx.dppass.core.JsonString
import com.dpsmpx.dppass.diagnostics.DiagCode
import com.dpsmpx.dppass.diagnostics.Diagnostic
import com.dpsmpx.dppass.diagnostics.Outcome
import com.dpsmpx.dppass.diagnostics.Secret
import com.dpsmpx.dppass.engine.LocalProxySpec
import com.dpsmpx.dppass.storage.BlobStore
import com.dpsmpx.dppass.storage.Quarantine
import java.io.IOException
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.security.SecureRandom

/**
 * Подключение без VPN (D-95): включено ли, порт, логин и пароль локального
 * прокси на `127.0.0.1`. Логин и пароль — секреты: только в зашифрованном
 * хранилище (D-19) и на экране настроек (`FLAG_SECURE`), в журнал не
 * пишутся. Порт и пароль — случайные (T11): известный порт без пароля
 * достался бы любому приложению устройства.
 */
data class LocalProxySettings(val enabled: Boolean, val port: Int, val user: Secret, val password: Secret) {
    init {
        require(port in ShareSettings.PORT_FROM until ShareSettings.PORT_UNTIL) {
            "порт локального прокси вне ${ShareSettings.PORT_FROM}..${ShareSettings.PORT_UNTIL - 1}"
        }
    }

    /** Вход для ядра; выключено — null. */
    fun spec(): LocalProxySpec? = if (enabled) LocalProxySpec(port, user, password) else null

    /** Ссылка для приложений, которые принимают её целиком (`socks5://…`); пароль в ней — только на экран. */
    fun link(): String = "socks5://${user.reveal()}:${password.reveal()}@${LocalProxySpec.ADDRESS}:$port"

    companion object {
        /** Новые случайные порт, логин и пароль; режим — выключен. */
        fun generate(random: SecureRandom = SecureRandom()): LocalProxySettings = LocalProxySettings(
            false,
            ShareSettings.PORT_FROM + random.nextInt(ShareSettings.PORT_UNTIL - ShareSettings.PORT_FROM),
            Secret(ShareSettings.word(random, ShareSettings.USER_LENGTH)),
            Secret(ShareSettings.word(random, ShareSettings.PASSWORD_LENGTH)),
        )
    }
}

/**
 * Документ `dppass.local-proxy` — запись `settings/local-proxy` (D-95).
 * Чтение строгое: что не читается, уходит в карантин (D-06), а не
 * становится прокси с чужим паролем.
 */
object LocalProxyCodec {
    const val FORMAT: String = "dppass.local-proxy"
    const val VERSION: Int = 1

    fun write(s: LocalProxySettings): String = Json.write(
        Json.obj(
            "format" to Json.str(FORMAT),
            "format_version" to Json.num(VERSION),
            "enabled" to Json.bool(s.enabled),
            "port" to Json.num(s.port),
            "user" to Json.str(s.user.reveal()),
            "password" to Json.str(s.password.reveal()),
        ),
        pretty = false,
    )

    fun read(text: String): Outcome<LocalProxySettings> {
        val root = try {
            Json.parse(text) as? JsonObject
        } catch (e: JsonParseException) {
            null
        } ?: return Outcome.failure(DiagCode.STORAGE_CORRUPTED, "настройки локального прокси — не объект JSON")
        fun bad(what: String): Outcome<LocalProxySettings> = Outcome.failure(DiagCode.STORAGE_CORRUPTED, "настройки локального прокси: $what")
        if ((root["format"] as? JsonString)?.value != FORMAT || (root["format_version"] as? JsonNumber)?.toIntOrNull() != VERSION) {
            return Outcome.failure(DiagCode.FORMAT_VERSION_UNSUPPORTED, "неизвестный формат настроек локального прокси")
        }
        root.fields.keys.firstOrNull { it !in KEYS }?.let { return bad("неизвестное поле «$it»") }
        val enabled = (root["enabled"] as? JsonBool)?.value ?: return bad("enabled")
        val port = (root["port"] as? JsonNumber)?.toIntOrNull()?.takeIf { it in ShareSettings.PORT_FROM until ShareSettings.PORT_UNTIL } ?: return bad("port")
        val user = (root["user"] as? JsonString)?.value?.takeIf { it.isNotEmpty() } ?: return bad("user")
        val password = (root["password"] as? JsonString)?.value?.takeIf { it.isNotEmpty() } ?: return bad("password")
        return Outcome.Success(LocalProxySettings(enabled, port, Secret(user), Secret(password)))
    }

    private val KEYS = setOf("format", "format_version", "enabled", "port", "user", "password")
}

/** Хранение настроек локального прокси одной записью (атомарно — от [BlobStore]). */
class LocalProxyStore(private val blobs: BlobStore, private val quarantine: Quarantine) {
    /** Записи нет — новые случайные настройки (режим выключен), они и сохраняются. */
    fun load(): Outcome<LocalProxySettings> {
        val bytes = when (val r = blobs.read(KEY)) {
            is Outcome.Failure -> return r
            is Outcome.Success -> r.value ?: return fresh()
        }
        return when (val parsed = LocalProxyCodec.read(String(bytes, Charsets.UTF_8))) {
            is Outcome.Success -> parsed
            is Outcome.Failure -> when (val kept = quarantine.keep("local-proxy", bytes, parsed.errors.first())) {
                is Outcome.Failure -> Outcome.Failure(
                    listOf(
                        Diagnostic.error(DiagCode.STORAGE_CORRUPTED, "настройки локального прокси не прочитаны и не сохранены в карантин")
                            .copy(causes = parsed.diagnostics + kept.diagnostics),
                    ),
                )
                is Outcome.Success -> when (val f = fresh()) {
                    is Outcome.Failure -> f
                    is Outcome.Success -> Outcome.Success(
                        f.value,
                        listOf(
                            Diagnostic.warning(
                                DiagCode.STORAGE_CORRUPTED,
                                "настройки локального прокси не прочитаны; исходник сохранён в карантин, режим без VPN выключен, пароль новый",
                            ).copy(causes = parsed.diagnostics),
                        ),
                    )
                }
            }
        }
    }

    fun save(s: LocalProxySettings): Outcome<Unit> = blobs.write(KEY, LocalProxyCodec.write(s).toByteArray(Charsets.UTF_8))

    private fun fresh(): Outcome<LocalProxySettings> {
        val s = LocalProxySettings.generate()
        return when (val w = save(s)) {
            is Outcome.Failure -> w
            is Outcome.Success -> Outcome.Success(s)
        }
    }

    companion object {
        const val KEY: String = "settings/local-proxy"
    }
}

/**
 * Подключение без VPN в приложении (D-95): прочитать, включить или
 * выключить, сменить порт и пароль, перед подключением — убедиться, что
 * порт свободен. Каждая смена сохраняется сразу.
 */
class LocalProxyService(
    private val store: LocalProxyStore,
    private val random: SecureRandom = SecureRandom(),
    /** Свободен ли порт на `127.0.0.1`; на хосте в тестах — подмена. */
    private val isFree: (Int) -> Boolean = LocalPorts::isFree,
) {
    @Volatile
    private var cached: LocalProxySettings? = null

    fun current(): Outcome<LocalProxySettings> = cached?.let { Outcome.Success(it) } ?: store.load().also { r ->
        if (r is Outcome.Success) cached = r.value
    }

    /** Включён ли режим; хранилище не читается — нет (подключение через VPN, как по умолчанию). */
    fun enabled(): Boolean = current().valueOrNull()?.enabled == true

    fun setEnabled(on: Boolean): Outcome<LocalProxySettings> = change { it.copy(enabled = on) }

    /** Новые порт, логин и пароль: приложения, где был указан прежний, надо настроить заново. */
    fun regenerate(): Outcome<LocalProxySettings> = change { LocalProxySettings.generate(random).copy(enabled = it.enabled) }

    /**
     * Вход для подключения: режим выключен — null. Порт занят другим
     * приложением — новый случайный (он и сохраняется, пароль прежний);
     * свободного не нашлось — отказ с причиной, до попыток серверов.
     */
    fun prepare(): Outcome<LocalProxySpec?> {
        val now = when (val c = current()) {
            is Outcome.Failure -> return c
            is Outcome.Success -> c.value
        }
        if (!now.enabled) return Outcome.Success(null)
        if (isFree(now.port)) return Outcome.Success(now.spec())
        repeat(PORT_TRIES) {
            val port = ShareSettings.PORT_FROM + random.nextInt(ShareSettings.PORT_UNTIL - ShareSettings.PORT_FROM)
            if (isFree(port)) {
                return when (val r = change { it.copy(port = port) }) {
                    is Outcome.Failure -> r
                    is Outcome.Success -> Outcome.Success(
                        r.value.spec(),
                        listOf(Diagnostic.info(DiagCode.LOCAL_PROXY_PORT_CHANGED, "порт ${now.port} локального прокси занят — новый порт $port")),
                    )
                }
            }
        }
        return Outcome.failure(DiagCode.LOCAL_PROXY_UNAVAILABLE, "для локального прокси не нашлось свободного порта на ${LocalProxySpec.ADDRESS}")
    }

    private fun change(f: (LocalProxySettings) -> LocalProxySettings): Outcome<LocalProxySettings> {
        val now = when (val c = current()) {
            is Outcome.Failure -> return c
            is Outcome.Success -> c.value
        }
        val next = f(now)
        return when (val w = store.save(next)) {
            is Outcome.Failure -> w
            is Outcome.Success -> Outcome.Success(next.also { cached = it })
        }
    }

    private companion object {
        const val PORT_TRIES = 20
    }
}

/**
 * Когда предлагать подключение без VPN (D-95): VPN не поднялся — согласия
 * нет, «Постоянный VPN» у другого приложения, система не дала TUN (на ПК —
 * нет прав на TUN) — а режим ещё не включён. Включает его только нажатие
 * пользователя: телефон и ПК решают одинаково.
 */
object LocalProxyOffer {
    fun applies(reason: Diagnostic, enabled: Boolean): Boolean = !enabled && reason.code == DiagCode.TUN_ESTABLISH_FAILED
}

/** Порты на `127.0.0.1` (D-95): занят ли порт — пробой привязки, без соединений наружу. */
object LocalPorts {
    private val LOOPBACK: InetAddress = InetAddress.getByAddress(byteArrayOf(127, 0, 0, 1))

    fun isFree(port: Int): Boolean = try {
        ServerSocket().use { it.bind(InetSocketAddress(LOOPBACK, port)) }
        true
    } catch (e: IOException) {
        false
    }
}
