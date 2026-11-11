package com.dpsmpx.dppass.config

import java.util.Base64

/** Стандартные ключи SS2022. Разбор не принимает произвольный пароль или пустые звенья. */
object ShadowsocksKeys {
    fun valid(key: String, bytes: Int = 32): Boolean =
        key.length <= 48 && runCatching { Base64.getDecoder().decode(key).size == bytes }.getOrDefault(false)

    fun canonical(key: String): String = Base64.getEncoder().encodeToString(Base64.getDecoder().decode(key))
}
