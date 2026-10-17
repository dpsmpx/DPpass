package com.dpsmpx.dppass.connection

import com.dpsmpx.dppass.config.ConfigValidator
import com.dpsmpx.dppass.config.ProtocolSpec
import com.dpsmpx.dppass.config.SecuritySpec
import com.dpsmpx.dppass.config.ServerProfile
import com.dpsmpx.dppass.config.TransportSpec
import com.dpsmpx.dppass.core.Cidr
import com.dpsmpx.dppass.core.Clock
import com.dpsmpx.dppass.core.Endpoint
import com.dpsmpx.dppass.core.Host
import com.dpsmpx.dppass.core.IpAddress
import com.dpsmpx.dppass.core.Json
import com.dpsmpx.dppass.core.JsonArray
import com.dpsmpx.dppass.core.JsonNumber
import com.dpsmpx.dppass.core.JsonObject
import com.dpsmpx.dppass.core.JsonParseException
import com.dpsmpx.dppass.core.JsonString
import com.dpsmpx.dppass.core.ProfileId
import com.dpsmpx.dppass.diagnostics.DiagCode
import com.dpsmpx.dppass.diagnostics.Diagnostic
import com.dpsmpx.dppass.diagnostics.Outcome
import com.dpsmpx.dppass.diagnostics.Secret
import com.dpsmpx.dppass.diagnostics.map
import com.dpsmpx.dppass.storage.BlobStore
import com.dpsmpx.dppass.storage.Quarantine
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.net.URLDecoder
import java.net.URLEncoder
import java.security.SecureRandom

/**
 * Устройство раздачи (D-55): другой телефон с DPpass, который раздаёт свой
 * туннель (D-51). Этот телефон подключается к его входу раздачи, как к
 * серверу, — SOCKS5 с логином и паролем.
 *
 * [address] — null: шлюз той сети, через которую этот телефон подключён к
 * устройству (его точка доступа Wi-Fi, Bluetooth- или USB-модем). Android
 * выбирает подсеть раздачи сам и меняет её от включения к включению, поэтому
 * адрес по умолчанию не запоминается. Явный адрес — только частный IPv4.
 */
data class RelayDevice(
    val id: String,
    val name: String,
    val address: IpAddress?,
    val port: Int,
    val user: Secret,
    val password: Secret,
    val addedAtMillis: Long,
) {
    val profileId: ProfileId get() = ProfileId("$PROFILE_PREFIX$id")

    /** Профиль для ядра: устройство по найденному адресу [at]. */
    fun profile(at: IpAddress): ServerProfile =
        ServerProfile(profileId, name, Endpoint(Host.Ip(at), port), ProtocolSpec.Socks(user, password), TransportSpec.Tcp, SecuritySpec.None)

    companion object {
        const val PROFILE_PREFIX: String = "relay."
    }
}

/** Что пользователь ввёл или принёс ссылкой; [address] пустой — шлюз сети. */
data class RelayDraft(val name: String, val address: String, val port: Int, val user: String, val password: String)

/**
 * Ссылка на вход раздачи (D-55): `socks5://логин:пароль@адрес:порт#имя` —
 * её отдаёт «Поделиться входом» на экране раздачи. Адрес — частный IPv4
 * (по нему видно, что ссылка про сеть раздачи), имя — необязательно.
 */
data class RelayLink(val address: IpAddress, val port: Int, val user: String, val password: String, val name: String?) {
    /** Черновик устройства: адрес — шлюз сети (подсеть раздачи меняется), имя — из ссылки или [fallbackName]. */
    fun draft(fallbackName: String): RelayDraft = RelayDraft(name?.takeIf { it.isNotBlank() } ?: fallbackName, "", port, user, password)

    fun format(): String = buildString {
        append(SCHEME).append(enc(user)).append(':').append(enc(password)).append('@').append(address).append(':').append(port)
        if (!name.isNullOrBlank()) append('#').append(enc(name))
    }

    companion object {
        const val SCHEME: String = "socks5://"
        private val SHAPE = Regex("""socks5://([^:@/\s]+):([^@/\s]+)@([0-9.]+):(\d{1,5})(?:#(\S*))?""", RegexOption.IGNORE_CASE)

        fun looksLike(text: String): Boolean = text.trim().startsWith(SCHEME, ignoreCase = true) && '\n' !in text.trim()

        /** Строгий разбор: не та форма, не частный IPv4, порт вне диапазона — причина, без значений из ссылки (T3). */
        fun parse(text: String): Outcome<RelayLink> {
            val m = SHAPE.matchEntire(text.trim())
                ?: return Outcome.failure(DiagCode.VALUE_UNKNOWN, "ссылка устройства раздачи — socks5://логин:пароль@адрес:порт")
            val user = dec(m.groupValues[1]) ?: return Outcome.failure(DiagCode.VALUE_UNKNOWN, "логин в ссылке не раскодирован")
            val password = dec(m.groupValues[2]) ?: return Outcome.failure(DiagCode.VALUE_UNKNOWN, "пароль в ссылке не раскодирован")
            val address = IpAddress.parseV4(m.groupValues[3])
            if (address == null || !Cidr.isPrivateV4(address)) {
                return Outcome.failure(DiagCode.RELAY_ADDRESS_NOT_LOCAL, "адрес в ссылке — не частный IPv4 своей сети")
            }
            val port = m.groupValues[4].toInt()
            if (port !in 1..65535) return Outcome.failure(DiagCode.PORT_INVALID, "порт вне 1..65535")
            val name = m.groupValues[5].takeIf { it.isNotEmpty() }?.let { dec(it) ?: return Outcome.failure(DiagCode.VALUE_UNKNOWN, "имя в ссылке не раскодировано") }
            return Outcome.Success(RelayLink(address, port, user, password, name))
        }

        // Имя кодировки строкой: перегрузка с Charset на Android — только с API 33.
        private fun enc(s: String): String = URLEncoder.encode(s, "UTF-8").replace("+", "%20")

        private fun dec(s: String): String? = runCatching { URLDecoder.decode(s.replace("+", "%2B"), "UTF-8") }.getOrNull()
    }
}

/**
 * Документ `dppass.relays` версии 1 — запись `settings/relays` (D-55).
 * Чтение строгое: что не читается, уходит в карантин (D-06), а список
 * начинается пустым — устройство с чужим паролем не появится «само».
 */
object RelayCodec {
    const val FORMAT: String = "dppass.relays"
    const val VERSION: Int = 1

    fun write(devices: List<RelayDevice>): String = Json.write(
        Json.obj(
            "format" to Json.str(FORMAT),
            "format_version" to Json.num(VERSION),
            "devices" to Json.arr(
                devices.map { d ->
                    Json.obj(
                        "id" to Json.str(d.id),
                        "name" to Json.str(d.name),
                        "address" to Json.str(d.address?.toString()),
                        "port" to Json.num(d.port),
                        "user" to Json.str(d.user.reveal()),
                        "password" to Json.str(d.password.reveal()),
                        "added_at" to Json.num(d.addedAtMillis),
                    )
                },
            ),
        ),
        pretty = false,
    )

    fun read(text: String): Outcome<List<RelayDevice>> {
        val root = try {
            Json.parse(text) as? JsonObject
        } catch (e: JsonParseException) {
            null
        } ?: return Outcome.failure(DiagCode.STORAGE_CORRUPTED, "устройства раздачи — не объект JSON")
        fun bad(what: String): Outcome<List<RelayDevice>> = Outcome.failure(DiagCode.STORAGE_CORRUPTED, "устройства раздачи: $what")
        if ((root["format"] as? JsonString)?.value != FORMAT || (root["format_version"] as? JsonNumber)?.toIntOrNull() != VERSION) {
            return Outcome.failure(DiagCode.FORMAT_VERSION_UNSUPPORTED, "неизвестный формат списка устройств раздачи")
        }
        root.fields.keys.firstOrNull { it !in ROOT_KEYS }?.let { return bad("неизвестное поле «$it»") }
        val items = (root["devices"] as? JsonArray)?.items ?: return bad("devices")
        val out = ArrayList<RelayDevice>()
        for ((i, item) in items.withIndex()) {
            val o = item as? JsonObject ?: return bad("devices[$i]")
            o.fields.keys.firstOrNull { it !in DEVICE_KEYS }?.let { return bad("devices[$i]: неизвестное поле «$it»") }
            val id = (o["id"] as? JsonString)?.value?.takeIf { ID.matches(it) } ?: return bad("devices[$i].id")
            val name = (o["name"] as? JsonString)?.value?.takeIf { RelayService.nameProblem(it) == null } ?: return bad("devices[$i].name")
            val address = when (val a = o["address"]) {
                null -> null
                is JsonString -> IpAddress.parseV4(a.value)?.takeIf(Cidr::isPrivateV4) ?: return bad("devices[$i].address")
                else -> return bad("devices[$i].address")
            }
            val port = (o["port"] as? JsonNumber)?.toIntOrNull()?.takeIf { it in 1..65535 } ?: return bad("devices[$i].port")
            val user = (o["user"] as? JsonString)?.value?.takeIf { it.isNotEmpty() } ?: return bad("devices[$i].user")
            val password = (o["password"] as? JsonString)?.value?.takeIf { it.isNotEmpty() } ?: return bad("devices[$i].password")
            val added = (o["added_at"] as? JsonNumber)?.toLongOrNull() ?: return bad("devices[$i].added_at")
            out += RelayDevice(id, name, address, port, Secret(user), Secret(password), added)
        }
        if (out.distinctBy { it.id }.size != out.size) return bad("повтор id")
        return Outcome.Success(out)
    }

    private val ROOT_KEYS = setOf("format", "format_version", "devices")
    private val DEVICE_KEYS = setOf("id", "name", "address", "port", "user", "password", "added_at")
    internal val ID = Regex("""[0-9a-f]{12}""")
}

/** Хранение списка одной записью (атомарно — от [BlobStore]). */
class RelayStore(private val blobs: BlobStore, private val quarantine: Quarantine) {
    /** Записи нет — пустой список. Не читается — в карантин, список пуст, причина — предупреждением. */
    fun load(): Outcome<List<RelayDevice>> {
        val bytes = when (val r = blobs.read(KEY)) {
            is Outcome.Failure -> return r
            is Outcome.Success -> r.value ?: return Outcome.Success(emptyList())
        }
        return when (val parsed = RelayCodec.read(String(bytes, Charsets.UTF_8))) {
            is Outcome.Success -> parsed
            is Outcome.Failure -> when (val kept = quarantine.keep("relays", bytes, parsed.errors.first())) {
                is Outcome.Failure -> Outcome.Failure(
                    listOf(
                        Diagnostic.error(DiagCode.STORAGE_CORRUPTED, "устройства раздачи не прочитаны и не сохранены в карантин")
                            .copy(causes = parsed.diagnostics + kept.diagnostics),
                    ),
                )
                is Outcome.Success -> when (val w = save(emptyList())) {
                    is Outcome.Failure -> w
                    is Outcome.Success -> Outcome.Success(
                        emptyList(),
                        listOf(
                            Diagnostic.warning(DiagCode.STORAGE_CORRUPTED, "список устройств раздачи не прочитан; исходник сохранён в карантин, список пуст")
                                .copy(causes = parsed.diagnostics),
                        ),
                    )
                }
            }
        }
    }

    fun save(devices: List<RelayDevice>): Outcome<Unit> = blobs.write(KEY, RelayCodec.write(devices).toByteArray(Charsets.UTF_8))

    companion object {
        const val KEY: String = "settings/relays"
    }
}

/**
 * Доверенные устройства раздачи (D-55): список, добавление вручную или по
 * ссылке, переименование, удаление. Каждая смена сохраняется сразу; что не
 * сохранилось, того нет. Устройство добавляет только пользователь: ни
 * документ, ни подписка его не несут (D-11).
 */
class RelayService(private val store: RelayStore, private val clock: Clock, private val random: SecureRandom = SecureRandom()) {
    @Volatile
    private var cached: List<RelayDevice>? = null

    fun list(): Outcome<List<RelayDevice>> = cached?.let { Outcome.Success(it) } ?: store.load().also { r ->
        if (r is Outcome.Success) cached = r.value
    }

    fun find(id: String): RelayDevice? = list().valueOrNull()?.firstOrNull { it.id == id }

    /** Проверить черновик и добавить; тот же адрес, порт и логин — обновить пароль и имя, а не плодить копию. */
    fun add(draft: RelayDraft): Outcome<RelayDevice> {
        val problems = validate(draft)
        if (problems.isNotEmpty()) return Outcome.Failure(problems)
        val address = draft.address.trim().takeIf { it.isNotEmpty() }?.let(IpAddress::parseV4)
        val now = when (val l = list()) {
            is Outcome.Failure -> return l
            is Outcome.Success -> l.value
        }
        val same = now.firstOrNull { it.address == address && it.port == draft.port && it.user.reveal() == draft.user }
        if (same == null && now.size >= MAX_DEVICES) {
            return Outcome.failure(DiagCode.LIMIT_EXCEEDED, "устройств раздачи не больше $MAX_DEVICES — удалите ненужное")
        }
        val device = RelayDevice(
            same?.id ?: newId(now),
            draft.name.trim(),
            address,
            draft.port,
            Secret(draft.user),
            Secret(draft.password),
            same?.addedAtMillis ?: clock.nowMillis(),
        )
        return save(if (same == null) now + device else now.map { if (it.id == same.id) device else it }).map { device }
    }

    fun rename(id: String, name: String): Outcome<RelayDevice> {
        nameProblem(name)?.let { return Outcome.failure(DiagCode.NAME_INVALID, it) }
        val now = when (val l = list()) {
            is Outcome.Failure -> return l
            is Outcome.Success -> l.value
        }
        val device = now.firstOrNull { it.id == id }?.copy(name = name.trim()) ?: return Outcome.failure(DiagCode.PROFILE_NOT_FOUND, "устройства раздачи нет")
        return save(now.map { if (it.id == id) device else it }).map { device }
    }

    fun remove(id: String): Outcome<Unit> {
        val now = when (val l = list()) {
            is Outcome.Failure -> return l
            is Outcome.Success -> l.value
        }
        return save(now.filterNot { it.id == id })
    }

    private fun save(next: List<RelayDevice>): Outcome<Unit> = store.save(next).also { if (it is Outcome.Success) cached = next }

    private fun newId(taken: List<RelayDevice>): String {
        while (true) {
            val bytes = ByteArray(ID_BYTES).also(random::nextBytes)
            val id = bytes.joinToString("") { "%02x".format(it) }
            if (taken.none { it.id == id }) return id
        }
    }

    companion object {
        const val MAX_DEVICES: Int = 16
        const val MAX_NAME: Int = 64

        /** Логин и пароль SOCKS5 — не длиннее 255 байт (RFC 1929). */
        const val MAX_CREDENTIAL_BYTES: Int = 255
        private const val ID_BYTES = 6

        /** Адрес-заглушка для проверки черновика без адреса: протокол проверяется тем же [ConfigValidator]. */
        private val PLACEHOLDER = IpAddress.parseV4("192.168.0.1")!!

        fun nameProblem(name: String): String? = when {
            name.isBlank() -> "имя не задано"
            name.trim().length > MAX_NAME -> "имя длиннее $MAX_NAME символов"
            name.any { it.isISOControl() } -> "в имени управляющий символ"
            else -> null
        }

        /** Причины, по которым черновик не станет устройством; пусто — годен. Значений из черновика в причинах нет (T3). */
        fun validate(draft: RelayDraft): List<Diagnostic> {
            val out = ArrayList<Diagnostic>()
            nameProblem(draft.name)?.let { out += Diagnostic.error(DiagCode.NAME_INVALID, it, "name") }
            val text = draft.address.trim()
            val address = if (text.isEmpty()) {
                PLACEHOLDER
            } else {
                IpAddress.parseV4(text)?.takeIf(Cidr::isPrivateV4).also {
                    if (it == null) {
                        out += Diagnostic.error(DiagCode.RELAY_ADDRESS_NOT_LOCAL, "адрес — частный IPv4 своей сети (192.168.x.x, 10.x.x.x, 172.16–31.x.x) или пусто — шлюз сети", "address")
                    }
                } ?: PLACEHOLDER
            }
            if (draft.port !in 1..65535) {
                out += Diagnostic.error(DiagCode.PORT_INVALID, "порт — от 1 до 65535", "port")
                return out
            }
            for ((value, field) in listOf(draft.user to "user", draft.password to "password")) {
                if (value.toByteArray(Charsets.UTF_8).size > MAX_CREDENTIAL_BYTES) {
                    out += Diagnostic.error(DiagCode.LIMIT_EXCEEDED, "длиннее $MAX_CREDENTIAL_BYTES байт — SOCKS5 столько не передаст", field)
                }
            }
            val profile = RelayDevice("000000000000", "check", address, draft.port, Secret(draft.user), Secret(draft.password), 0).profile(address)
            out += ConfigValidator.validateProfile(profile, "relay").map { d -> d.copy(path = d.path?.substringAfterLast('.')) }
            return out.distinctBy { it.code to it.path }
        }
    }
}

/**
 * Проверка входа раздачи по протоколу (D-55, RFC 1928 и 1929): приветствие
 * с единственным методом «логин и пароль», затем логин и пароль. Только
 * разговор с потоками — сокет, привязанный к нужной сети, даёт оболочка.
 * Ничего, кроме входа, не запрашивается: соединение закрывается сразу.
 */
object Socks5Login {
    enum class Result {
        /** Вход раздачи принял логин и пароль. */
        ACCEPTED,

        /** Это SOCKS5, но логин или пароль не подошли. */
        REJECTED,

        /** Ответ — не SOCKS5 с паролем: по адресу не вход раздачи. */
        NOT_SOCKS,
    }

    @Throws(IOException::class)
    fun check(input: InputStream, output: OutputStream, user: Secret, password: Secret): Result {
        val u = user.reveal().toByteArray(Charsets.UTF_8)
        val p = password.reveal().toByteArray(Charsets.UTF_8)
        require(u.size in 1..255 && p.size in 1..255) { "логин и пароль SOCKS5 — от 1 до 255 байт" }
        output.write(byteArrayOf(VERSION, 1, METHOD_PASSWORD))
        output.flush()
        val method = readExactly(input, 2) ?: return Result.NOT_SOCKS
        if (method[0] != VERSION || method[1] != METHOD_PASSWORD) return Result.NOT_SOCKS
        output.write(byteArrayOf(AUTH_VERSION, u.size.toByte()) + u + byteArrayOf(p.size.toByte()) + p)
        output.flush()
        val status = readExactly(input, 2) ?: return Result.NOT_SOCKS
        if (status[0] != AUTH_VERSION) return Result.NOT_SOCKS
        return if (status[1].toInt() == 0) Result.ACCEPTED else Result.REJECTED
    }

    private fun readExactly(input: InputStream, n: Int): ByteArray? {
        val out = ByteArray(n)
        var got = 0
        while (got < n) {
            val r = input.read(out, got, n - got)
            if (r < 0) return null
            got += r
        }
        return out
    }

    private const val VERSION: Byte = 5
    private const val METHOD_PASSWORD: Byte = 2
    private const val AUTH_VERSION: Byte = 1
}
