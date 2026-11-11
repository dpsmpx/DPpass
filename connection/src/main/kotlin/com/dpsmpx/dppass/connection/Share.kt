package com.dpsmpx.dppass.connection

import com.dpsmpx.dppass.config.ShadowsocksKeys
import com.dpsmpx.dppass.core.Json
import com.dpsmpx.dppass.core.JsonArray
import com.dpsmpx.dppass.core.JsonBool
import com.dpsmpx.dppass.core.JsonNumber
import com.dpsmpx.dppass.core.JsonObject
import com.dpsmpx.dppass.core.JsonParseException
import com.dpsmpx.dppass.core.JsonString
import com.dpsmpx.dppass.diagnostics.DiagCode
import com.dpsmpx.dppass.diagnostics.Diagnostic
import com.dpsmpx.dppass.diagnostics.Outcome
import com.dpsmpx.dppass.diagnostics.Secret
import com.dpsmpx.dppass.engine.ShareSpec
import com.dpsmpx.dppass.storage.BlobStore
import com.dpsmpx.dppass.storage.Quarantine
import java.security.SecureRandom
import java.util.Base64

/**
 * Сопряжённое устройство (D-56): свой вход раздачи — логин и пароль,
 * выданные при сопряжении. Удалить — отозвать доверие только у него.
 */
data class PairedDevice(val id: String, val name: String, val user: Secret, val password: Secret, val pairedAtMillis: Long)

/**
 * Раздача туннеля другим устройствам (D-110): включена ли, порт, ключ сервера и
 * ключ клиента, сопряжённые устройства со своими входами (D-56). Ключи и
 * пароли — секреты: пишутся только в зашифрованное хранилище (D-19),
 * наружу — только на экран настроек (`FLAG_SECURE`) и сопряжённому
 * устройству шифрованным каналом.
 */
data class ShareSettings(val enabled: Boolean, val port: Int, val user: Secret, val password: Secret, val paired: List<PairedDevice> = emptyList()) {
    init {
        require(port in PORT_FROM until PORT_UNTIL) { "порт раздачи вне $PORT_FROM..${PORT_UNTIL - 1}" }
        require((listOf(user) + paired.map { it.user }).distinct().size == paired.size + 1) { "логин входа раздачи повторяется" }
    }

    /** Вход для ядра на этих интерфейсах раздачи; раздача выключена или интерфейсов нет — null. */
    fun spec(endpoints: List<ShareSpec.Endpoint>): ShareSpec? {
        val usable = endpoints.distinctBy { it.address }
        return if (enabled && usable.isNotEmpty()) ShareSpec(usable, port, user, password, paired.map { ShareSpec.Account(it.user, it.password) }) else null
    }

    companion object {
        /** Случайный порт — из этого диапазона (T11: не известный порт прокси). */
        const val PORT_FROM: Int = 20000
        const val PORT_UNTIL: Int = 60000
        const val USER_LENGTH: Int = 44
        const val PASSWORD_LENGTH: Int = 44

        /** Сопряжённых устройств не больше: у каждого — свой вход ядра. */
        const val MAX_PAIRED: Int = 8
        private const val ALPHABET = "abcdefghijkmnpqrstuvwxyz23456789"

        internal fun key(random: SecureRandom): String = Base64.getEncoder().encodeToString(ByteArray(32).also(random::nextBytes))

        internal fun word(random: SecureRandom, n: Int): String = String(CharArray(n) { ALPHABET[random.nextInt(ALPHABET.length)] })

        /** Новые случайные порт, логин и пароль (D-51); раздача — выключена, сопряжённых нет. */
        fun generate(random: SecureRandom = SecureRandom()): ShareSettings =
            ShareSettings(false, PORT_FROM + random.nextInt(PORT_UNTIL - PORT_FROM), Secret(key(random)), Secret(key(random)))
    }
}

/**
 * Документ `dppass.share` — запись `settings/share` (D-110). Версия 3
 * содержит ключи SS2022; старые версии 1/2 не активируются и требуют
 * повторного сопряжения. Чтение строгое: что не читается, уходит в карантин
 * (D-06), а не становится «раздачей по умолчанию» с чужим паролем.
 */
object ShareCodec {
    const val FORMAT: String = "dppass.share"
    const val VERSION: Int = 3
    val READABLE: Set<Int> = setOf(VERSION)

    fun write(s: ShareSettings): String = Json.write(
        Json.obj(
            "format" to Json.str(FORMAT),
            "format_version" to Json.num(VERSION),
            "enabled" to Json.bool(s.enabled),
            "port" to Json.num(s.port),
            "server_key" to Json.str(s.user.reveal()),
            "client_key" to Json.str(s.password.reveal()),
            "devices" to Json.arr(
                s.paired.map { d ->
                    Json.obj(
                        "id" to Json.str(d.id),
                        "name" to Json.str(d.name),
                        "user" to Json.str(d.user.reveal()),
                        "client_key" to Json.str(d.password.reveal()),
                        "paired_at" to Json.num(d.pairedAtMillis),
                    )
                },
            ),
        ),
        pretty = false,
    )

    fun read(text: String): Outcome<ShareSettings> {
        val root = try {
            Json.parse(text) as? JsonObject
        } catch (e: JsonParseException) {
            null
        } ?: return Outcome.failure(DiagCode.STORAGE_CORRUPTED, "настройки раздачи — не объект JSON")
        fun bad(what: String): Outcome<ShareSettings> = Outcome.failure(DiagCode.STORAGE_CORRUPTED, "настройки раздачи: $what")
        val version = (root["format_version"] as? JsonNumber)?.toIntOrNull()
        if ((root["format"] as? JsonString)?.value != FORMAT || version !in READABLE) {
            return Outcome.failure(
                DiagCode.FORMAT_VERSION_UNSUPPORTED,
                "старый или неизвестный формат раздачи: обновите оба устройства и выполните сопряжение заново",
            )
        }
        val known = setOf("format", "format_version", "enabled", "port", "server_key", "client_key") + if (version == 1) emptySet() else setOf("devices")
        root.fields.keys.firstOrNull { it !in known }?.let { return bad("неизвестное поле «$it»") }
        val enabled = (root["enabled"] as? JsonBool)?.value ?: return bad("enabled")
        val port = (root["port"] as? JsonNumber)?.toIntOrNull()?.takeIf { it in ShareSettings.PORT_FROM until ShareSettings.PORT_UNTIL } ?: return bad("port")
        val user = (root["server_key"] as? JsonString)?.value?.takeIf { ShadowsocksKeys.valid(it) } ?: return bad("user")
        val password = (root["client_key"] as? JsonString)?.value?.takeIf { ShadowsocksKeys.valid(it) } ?: return bad("password")
        val paired = ArrayList<PairedDevice>()
        if (version != 1) {
            val items = (root["devices"] as? JsonArray)?.items ?: return bad("devices")
            for ((i, item) in items.withIndex()) {
                val o = item as? JsonObject ?: return bad("devices[$i]")
                o.fields.keys.firstOrNull { it !in DEVICE_KEYS }?.let { return bad("devices[$i]: неизвестное поле «$it»") }
                val id = (o["id"] as? JsonString)?.value?.takeIf { RelayCodec.ID.matches(it) } ?: return bad("devices[$i].id")
                val name = (o["name"] as? JsonString)?.value?.takeIf { RelayService.nameProblem(it) == null } ?: return bad("devices[$i].name")
                val u = (o["user"] as? JsonString)?.value?.takeIf { it.isNotEmpty() } ?: return bad("devices[$i].user")
                val p = (o["client_key"] as? JsonString)?.value?.takeIf { ShadowsocksKeys.valid(it) } ?: return bad("devices[$i].password")
                val at = (o["paired_at"] as? JsonNumber)?.toLongOrNull() ?: return bad("devices[$i].paired_at")
                paired += PairedDevice(id, name, Secret(u), Secret(p), at)
            }
            if (paired.size > ShareSettings.MAX_PAIRED || paired.distinctBy { it.id }.size != paired.size) return bad("devices")
        }
        if ((listOf(user) + paired.map { it.user.reveal() }).distinct().size != paired.size + 1) return bad("логин повторяется")
        return Outcome.Success(ShareSettings(enabled, port, Secret(user), Secret(password), paired))
    }

    private val DEVICE_KEYS = setOf("id", "name", "user", "client_key", "paired_at")
}

/** Хранение настроек раздачи одной записью (атомарно — от [BlobStore]). */
class ShareStore(private val blobs: BlobStore, private val quarantine: Quarantine) {
    /** Записи нет — новые случайные настройки (раздача выключена), они и сохраняются. */
    fun load(): Outcome<ShareSettings> {
        val bytes = when (val r = blobs.read(KEY)) {
            is Outcome.Failure -> return r
            is Outcome.Success -> r.value ?: return fresh()
        }
        return when (val parsed = ShareCodec.read(String(bytes, Charsets.UTF_8))) {
            is Outcome.Success -> parsed
            is Outcome.Failure -> when (val kept = quarantine.keep("share", bytes, parsed.errors.first())) {
                is Outcome.Failure -> Outcome.Failure(
                    listOf(
                        Diagnostic.error(DiagCode.STORAGE_CORRUPTED, "настройки раздачи не прочитаны и не сохранены в карантин")
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
                                "настройки раздачи не прочитаны; исходник сохранён в карантин, раздача выключена, ключи новые; обновите оба устройства и выполните сопряжение заново",
                            )
                                .copy(causes = parsed.diagnostics),
                        ),
                    )
                }
            }
        }
    }

    fun save(s: ShareSettings): Outcome<Unit> = blobs.write(KEY, ShareCodec.write(s).toByteArray(Charsets.UTF_8))

    private fun fresh(): Outcome<ShareSettings> {
        val s = ShareSettings.generate()
        return when (val w = save(s)) {
            is Outcome.Failure -> w
            is Outcome.Success -> Outcome.Success(s)
        }
    }

    companion object {
        const val KEY: String = "settings/share"
    }
}

/**
 * Раздача в приложении (D-51): прочитать, включить или выключить, сменить
 * логин и пароль. Каждая смена сохраняется сразу; что не сохранилось,
 * того нет. Переподключение туннеля с новыми входами — дело оболочки.
 */
class ShareService(private val store: ShareStore, private val random: SecureRandom = SecureRandom()) {
    @Volatile
    private var cached: ShareSettings? = null

    fun current(): Outcome<ShareSettings> = cached?.let { Outcome.Success(it) } ?: store.load().also { r ->
        if (r is Outcome.Success) cached = r.value
    }

    fun setEnabled(on: Boolean): Outcome<ShareSettings> = change { it.copy(enabled = on) }

    /**
     * Новые порт, логин и пароль: прежние другие устройства больше не подойдут
     * — и сопряжённые тоже, их список очищается (D-56).
     */
    fun regenerate(): Outcome<ShareSettings> = change { ShareSettings.generate(random).copy(enabled = it.enabled) }

    /**
     * Сопряжение (D-56): новый вход только для этого устройства — свой логин и
     * пароль. Не сохранилось — входа нет и выдавать нечего.
     */
    fun pair(name: String, nowMillis: Long): Outcome<PairedDevice> {
        RelayService.nameProblem(name)?.let { return Outcome.failure(DiagCode.NAME_INVALID, it) }
        val now = when (val c = current()) {
            is Outcome.Failure -> return c
            is Outcome.Success -> c.value
        }
        if (now.paired.size >= ShareSettings.MAX_PAIRED) {
            return Outcome.failure(DiagCode.LIMIT_EXCEEDED, "сопряжённых устройств не больше ${ShareSettings.MAX_PAIRED} — уберите ненужное")
        }
        val taken = (listOf(now.user) + now.paired.map { it.user }).map { it.reveal() }.toSet()
        var user: String
        do user = "d" + ShareSettings.word(random, 11) while (user in taken)
        val id = ByteArray(6).also(random::nextBytes).joinToString("") { "%02x".format(it) }
        val device = PairedDevice(id, name.trim(), Secret(user), Secret(ShareSettings.key(random)), nowMillis)
        return change { it.copy(paired = it.paired + device) }.let { r -> if (r is Outcome.Failure) r else Outcome.Success(device) }
    }

    /** Отозвать доверие (D-56): вход этого устройства перестаёт действовать после переподключения. */
    fun unpair(id: String): Outcome<ShareSettings> = change { s -> s.copy(paired = s.paired.filterNot { it.id == id }) }

    private fun change(f: (ShareSettings) -> ShareSettings): Outcome<ShareSettings> {
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
}
