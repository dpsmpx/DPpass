package com.dpsmpx.dppass.app.paths

import android.security.keystore.KeyGenParameterSpec
import java.io.InputStream
import java.io.OutputStream
import java.security.Key
import java.security.KeyStoreSpi
import java.security.Provider
import java.security.SecureRandom
import java.security.Security
import java.security.cert.Certificate
import java.security.spec.AlgorithmParameterSpec
import java.util.Collections
import java.util.Date
import java.util.Enumeration
import java.util.concurrent.ConcurrentHashMap
import javax.crypto.KeyGenerator
import javax.crypto.KeyGeneratorSpi
import javax.crypto.SecretKey

/**
 * Хранилище ключей Android в песочнице (D-90). В Robolectric нет
 * `AndroidKeyStore`, а без ключа-обёртки данные приложения не сохраняются
 * (D-19, `KeystoreKeyWrapper`). Здесь — ключ AES в памяти процесса теста
 * под тем же именем; неизвлекаемость ключа не воспроизводится — тесты пути
 * проверяют экраны, а не Keystore. Только в `src/robolectric`: в APK не
 * попадает.
 */
object SandboxKeyStore {
    private const val NAME = "AndroidKeyStore"
    private val keys = ConcurrentHashMap<String, SecretKey>()

    fun install() {
        if (Security.getProvider(NAME) == null) Security.addProvider(Keys())
    }

    class Keys : Provider(NAME, 1.0, "ключи в памяти теста (D-90)") {
        init {
            put("KeyStore.$NAME", Store::class.java.name)
            put("KeyGenerator.AES", Generator::class.java.name)
        }
    }

    class Store : KeyStoreSpi() {
        override fun engineGetKey(alias: String, password: CharArray?): Key? = keys[alias]

        override fun engineGetCertificateChain(alias: String): Array<Certificate>? = null

        override fun engineGetCertificate(alias: String): Certificate? = null

        override fun engineGetCreationDate(alias: String): Date? = null

        override fun engineSetKeyEntry(alias: String, key: Key, password: CharArray?, chain: Array<out Certificate>?) {
            keys[alias] = key as SecretKey
        }

        override fun engineSetKeyEntry(alias: String, key: ByteArray, chain: Array<out Certificate>?) = throw UnsupportedOperationException()

        override fun engineSetCertificateEntry(alias: String, cert: Certificate) = throw UnsupportedOperationException()

        override fun engineDeleteEntry(alias: String) {
            keys.remove(alias)
        }

        override fun engineAliases(): Enumeration<String> = Collections.enumeration(keys.keys.toList())

        override fun engineContainsAlias(alias: String): Boolean = keys.containsKey(alias)

        override fun engineSize(): Int = keys.size

        override fun engineIsKeyEntry(alias: String): Boolean = keys.containsKey(alias)

        override fun engineIsCertificateEntry(alias: String): Boolean = false

        override fun engineGetCertificateAlias(cert: Certificate): String? = null

        override fun engineStore(stream: OutputStream?, password: CharArray?) = Unit

        override fun engineLoad(stream: InputStream?, password: CharArray?) = Unit
    }

    /** Ключ под именем из `KeyGenParameterSpec` — как у Android Keystore; сам ключ — от JDK. */
    class Generator : KeyGeneratorSpi() {
        private var alias: String? = null
        private var bits = 256

        override fun engineInit(random: SecureRandom?) = Unit

        override fun engineInit(params: AlgorithmParameterSpec, random: SecureRandom?) {
            val spec = params as KeyGenParameterSpec
            alias = spec.keystoreAlias
            bits = spec.keySize
        }

        override fun engineInit(keysize: Int, random: SecureRandom?) {
            bits = keysize
        }

        override fun engineGenerateKey(): SecretKey {
            val key = KeyGenerator.getInstance("AES", "SunJCE").apply { init(bits, SecureRandom()) }.generateKey()
            alias?.let { keys[it] = key }
            return key
        }
    }
}
