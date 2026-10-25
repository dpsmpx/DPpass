package com.dpsmpx.dppass.diagnostics

/**
 * Категория отказа — то, что видит пользователь вместо «Proxy error».
 *
 * Набор закрыт и мал: категория отвечает на вопрос «что сломалось»,
 * а подробность — у [DiagCode].
 */
enum class FailureKind {
    NETWORK_UNREACHABLE,
    DNS_RESOLUTION_FAILED,
    CONFIG_PARSE_FAILED,
    CONFIG_FORMAT_UNSUPPORTED,
    CONFIG_VALIDATION_FAILED,
    CAPABILITY_UNSUPPORTED,
    ROUTE_COMPILATION_FAILED,
    BACKEND_VALIDATION_FAILED,
    BACKEND_START_FAILED,
    TUN_START_FAILED,
    ENDPOINT_UNREACHABLE,
    TLS_HANDSHAKE_FAILED,
    AUTHENTICATION_FAILED,
    HEALTH_CHECK_FAILED,
    SUBSCRIPTION_FETCH_FAILED,
    SUBSCRIPTION_INVALID,
    STORAGE_FAILED,
    INTERNAL,
}

enum class Severity { INFO, WARNING, ERROR }

/**
 * Стабильный код диагностики.
 *
 * Имя кода — публичный контракт: по нему пишутся ожидания корпуса
 * регрессий (`tests/data/`) и будущие переводы сообщений. Коды не
 * переименовываются и не удаляются — только добавляются
 * (docs/ARCHITECTURE.md, «Диагностика»).
 */
enum class DiagCode(val kind: FailureKind, val defaultSeverity: Severity) {
    // --- разбор документа ---
    DOCUMENT_EMPTY(FailureKind.CONFIG_PARSE_FAILED, Severity.ERROR),
    DOCUMENT_TOO_LARGE(FailureKind.CONFIG_PARSE_FAILED, Severity.ERROR),
    DOCUMENT_TOO_DEEP(FailureKind.CONFIG_PARSE_FAILED, Severity.ERROR),
    JSON_SYNTAX(FailureKind.CONFIG_PARSE_FAILED, Severity.ERROR),
    JSON_DUPLICATE_KEY(FailureKind.CONFIG_PARSE_FAILED, Severity.ERROR),
    FIELD_MISSING(FailureKind.CONFIG_PARSE_FAILED, Severity.ERROR),
    FIELD_TYPE(FailureKind.CONFIG_PARSE_FAILED, Severity.ERROR),
    FIELD_UNKNOWN(FailureKind.CONFIG_PARSE_FAILED, Severity.ERROR),
    VALUE_UNKNOWN(FailureKind.CONFIG_PARSE_FAILED, Severity.ERROR),

    // --- формат и миграции ---
    FORMAT_NOT_DPPASS(FailureKind.CONFIG_FORMAT_UNSUPPORTED, Severity.ERROR),
    FORMAT_VERSION_MISSING(FailureKind.CONFIG_FORMAT_UNSUPPORTED, Severity.ERROR),
    FORMAT_VERSION_UNSUPPORTED(FailureKind.CONFIG_FORMAT_UNSUPPORTED, Severity.ERROR),
    MIGRATION_FAILED(FailureKind.CONFIG_FORMAT_UNSUPPORTED, Severity.ERROR),
    MIGRATION_APPLIED(FailureKind.CONFIG_FORMAT_UNSUPPORTED, Severity.INFO),

    // --- проверка конфигурации ---
    ID_INVALID(FailureKind.CONFIG_VALIDATION_FAILED, Severity.ERROR),
    ID_DUPLICATE(FailureKind.CONFIG_VALIDATION_FAILED, Severity.ERROR),
    REFERENCE_UNKNOWN(FailureKind.CONFIG_VALIDATION_FAILED, Severity.ERROR),
    NAME_INVALID(FailureKind.CONFIG_VALIDATION_FAILED, Severity.ERROR),
    HOST_INVALID(FailureKind.CONFIG_VALIDATION_FAILED, Severity.ERROR),
    PORT_INVALID(FailureKind.CONFIG_VALIDATION_FAILED, Severity.ERROR),
    UUID_INVALID(FailureKind.CONFIG_VALIDATION_FAILED, Severity.ERROR),
    PASSWORD_EMPTY(FailureKind.CONFIG_VALIDATION_FAILED, Severity.ERROR),
    PASSWORD_FORMAT_INVALID(FailureKind.CONFIG_VALIDATION_FAILED, Severity.ERROR),
    SECRET_PLACEHOLDER(FailureKind.CONFIG_VALIDATION_FAILED, Severity.ERROR),
    PATH_INVALID(FailureKind.CONFIG_VALIDATION_FAILED, Severity.ERROR),
    SERVER_NAME_INVALID(FailureKind.CONFIG_VALIDATION_FAILED, Severity.ERROR),
    REALITY_PUBLIC_KEY_INVALID(FailureKind.CONFIG_VALIDATION_FAILED, Severity.ERROR),
    REALITY_SHORT_ID_INVALID(FailureKind.CONFIG_VALIDATION_FAILED, Severity.ERROR),
    FLOW_REQUIRES_TCP_TLS(FailureKind.CONFIG_VALIDATION_FAILED, Severity.ERROR),
    SECURITY_REQUIRED(FailureKind.CONFIG_VALIDATION_FAILED, Severity.ERROR),
    TRANSPORT_PROTOCOL_MISMATCH(FailureKind.CONFIG_VALIDATION_FAILED, Severity.ERROR),
    INSECURE_TLS_REJECTED(FailureKind.CONFIG_VALIDATION_FAILED, Severity.ERROR),
    PROFILES_EMPTY(FailureKind.CONFIG_VALIDATION_FAILED, Severity.ERROR),
    LIMIT_EXCEEDED(FailureKind.CONFIG_VALIDATION_FAILED, Severity.ERROR),
    RULE_EMPTY(FailureKind.CONFIG_VALIDATION_FAILED, Severity.ERROR),
    RULE_DUPLICATE(FailureKind.CONFIG_VALIDATION_FAILED, Severity.WARNING),
    RULE_SHADOWED(FailureKind.CONFIG_VALIDATION_FAILED, Severity.WARNING),
    RULE_VALUE_DUPLICATE(FailureKind.CONFIG_VALIDATION_FAILED, Severity.INFO),
    DOMAIN_INVALID(FailureKind.CONFIG_VALIDATION_FAILED, Severity.ERROR),
    CIDR_INVALID(FailureKind.CONFIG_VALIDATION_FAILED, Severity.ERROR),
    CIDR_HOST_BITS(FailureKind.CONFIG_VALIDATION_FAILED, Severity.INFO),
    PACKAGE_INVALID(FailureKind.CONFIG_VALIDATION_FAILED, Severity.ERROR),
    GEO_CODE_INVALID(FailureKind.CONFIG_VALIDATION_FAILED, Severity.ERROR),
    PORT_RANGE_INVALID(FailureKind.CONFIG_VALIDATION_FAILED, Severity.ERROR),
    APP_POLICY_CONFLICT(FailureKind.CONFIG_VALIDATION_FAILED, Severity.ERROR),
    DNS_SERVER_INVALID(FailureKind.CONFIG_VALIDATION_FAILED, Severity.ERROR),
    DNS_SERVERS_EMPTY(FailureKind.CONFIG_VALIDATION_FAILED, Severity.ERROR),
    DNS_LEAK_RISK(FailureKind.CONFIG_VALIDATION_FAILED, Severity.WARNING),

    /**
     * Настройка транспорта вне допустимого (формат 2, D-37): диапазон не
     * «N» или «N-M», ноль там, где Xray его не принимает, `xmux` с обоими
     * пределами мультиплексирования.
     */
    TRANSPORT_SETTING_INVALID(FailureKind.CONFIG_VALIDATION_FAILED, Severity.ERROR),

    /**
     * Адрес устройства раздачи (D-55) — не частный IPv4 своей сети:
     * SOCKS передаёт логин, пароль и трафик открыто, в интернет так нельзя.
     */
    RELAY_ADDRESS_NOT_LOCAL(FailureKind.CONFIG_VALIDATION_FAILED, Severity.ERROR),

    /** Настройка учёта трафика вне допустимого (D-92): день начала периода не 1…31, порог не больше нуля или больше 1 ПиБ. */
    USAGE_SETTING_INVALID(FailureKind.CONFIG_VALIDATION_FAILED, Severity.ERROR),

    // --- возможности ядра и компиляция ---
    CAPABILITY_PROTOCOL_UNSUPPORTED(FailureKind.CAPABILITY_UNSUPPORTED, Severity.ERROR),
    CAPABILITY_TRANSPORT_UNSUPPORTED(FailureKind.CAPABILITY_UNSUPPORTED, Severity.ERROR),
    CAPABILITY_SECURITY_UNSUPPORTED(FailureKind.CAPABILITY_UNSUPPORTED, Severity.ERROR),
    CAPABILITY_FEATURE_UNSUPPORTED(FailureKind.CAPABILITY_UNSUPPORTED, Severity.ERROR),
    PROFILE_EXCLUDED_UNSUPPORTED(FailureKind.CAPABILITY_UNSUPPORTED, Severity.WARNING),
    SEMANTIC_FALLBACK(FailureKind.CAPABILITY_UNSUPPORTED, Severity.WARNING),
    ROUTE_COMPILE_FAILED(FailureKind.ROUTE_COMPILATION_FAILED, Severity.ERROR),
    PROFILE_NOT_FOUND(FailureKind.ROUTE_COMPILATION_FAILED, Severity.ERROR),

    /**
     * Кода geoip/geosite или атрибута списка нет в наборе геоданных ядра
     * (D-27): правило с ним молча не сработало бы никогда (D-05).
     */
    GEO_CODE_UNKNOWN(FailureKind.ROUTE_COMPILATION_FAILED, Severity.ERROR),

    /**
     * Разбиение ClientHello (D-68) включено, но у сервера нет TLS поверх TCP
     * (Hysteria2, XHTTP по h3 — это QUIC; без TLS и у устройства раздачи
     * ClientHello нет): разбивать нечего, сервер подключается как есть.
     */
    CLIENT_HELLO_SPLIT_NOT_APPLIED(FailureKind.CAPABILITY_UNSUPPORTED, Severity.WARNING),

    // --- ядро ---
    BACKEND_REJECTED_CONFIG(FailureKind.BACKEND_VALIDATION_FAILED, Severity.ERROR),
    BACKEND_START_FAILED(FailureKind.BACKEND_START_FAILED, Severity.ERROR),
    BACKEND_NOT_AVAILABLE(FailureKind.BACKEND_START_FAILED, Severity.ERROR),
    BACKEND_ALREADY_RUNNING(FailureKind.BACKEND_START_FAILED, Severity.ERROR),
    TUN_ESTABLISH_FAILED(FailureKind.TUN_START_FAILED, Severity.ERROR),

    /** Ядро занято: проверены сборка и политика, полная проверка — при запуске (D-25). */
    BACKEND_VALIDATION_PARTIAL(FailureKind.BACKEND_VALIDATION_FAILED, Severity.INFO),

    /**
     * Набор геоданных ядра не установлен (D-27): в APK его нет, он не
     * совпал со своим оглавлением или не записался. Ядро работает, но
     * конфигурации с geoip/geosite отвергает.
     */
    GEODATA_UNAVAILABLE(FailureKind.BACKEND_START_FAILED, Severity.ERROR),

    /**
     * Локальный прокси подключения без VPN (D-95) не поднялся: порт на
     * 127.0.0.1 занят другим приложением, свободного не нашлось. Это отказ
     * устройства, а не сервера: серверы не наказываются.
     */
    LOCAL_PROXY_UNAVAILABLE(FailureKind.BACKEND_START_FAILED, Severity.ERROR),

    /** Порт локального прокси был занят — выбран новый (D-95): приложения надо настроить на него. */
    LOCAL_PROXY_PORT_CHANGED(FailureKind.BACKEND_START_FAILED, Severity.INFO),

    // --- подключение и здоровье ---
    NETWORK_OFFLINE(FailureKind.NETWORK_UNREACHABLE, Severity.ERROR),
    DNS_FAILED(FailureKind.DNS_RESOLUTION_FAILED, Severity.ERROR),
    ENDPOINT_UNREACHABLE(FailureKind.ENDPOINT_UNREACHABLE, Severity.ERROR),
    TLS_HANDSHAKE_FAILED(FailureKind.TLS_HANDSHAKE_FAILED, Severity.ERROR),
    AUTHENTICATION_FAILED(FailureKind.AUTHENTICATION_FAILED, Severity.ERROR),
    PAYLOAD_STALLED(FailureKind.HEALTH_CHECK_FAILED, Severity.ERROR),
    HEALTH_CHECK_FAILED(FailureKind.HEALTH_CHECK_FAILED, Severity.ERROR),
    NO_VIABLE_CANDIDATE(FailureKind.ENDPOINT_UNREACHABLE, Severity.ERROR),
    ATTEMPTS_EXHAUSTED(FailureKind.ENDPOINT_UNREACHABLE, Severity.ERROR),

    /**
     * Здоровье не проверено (D-32): в DNS конфигурации нет сервера через
     * туннель, через который прошла бы проба. Подключение не отвергается,
     * но и не считается проверенным.
     */
    HEALTH_CHECK_SKIPPED(FailureKind.HEALTH_CHECK_FAILED, Severity.WARNING),

    /**
     * Устройство раздачи (D-55) не найдено: ни в одной сети телефона (Wi-Fi,
     * Bluetooth, USB) по его адресу не ответил вход раздачи с этим логином.
     */
    RELAY_NOT_FOUND(FailureKind.ENDPOINT_UNREACHABLE, Severity.ERROR),

    /** Сопряжение (D-56): ни в одной сети телефона раздающий телефон не ждёт сопряжения. */
    PAIRING_NOT_FOUND(FailureKind.ENDPOINT_UNREACHABLE, Severity.ERROR),

    /** Сопряжение (D-56): код не подтверждён на одном из телефонов — входа нет. */
    PAIRING_REFUSED(FailureKind.AUTHENTICATION_FAILED, Severity.ERROR),

    /**
     * Сопряжение (D-56) нарушено: не тот протокол, чужая кривая, не сошлось
     * обязательство или не расшифровался вход — возможна подмена.
     */
    PAIRING_BROKEN(FailureKind.AUTHENTICATION_FAILED, Severity.ERROR),

    /**
     * Через устройство раздачи (D-55, D-59) данные не идут: вход раздачи
     * принял логин и пароль, а проверка здоровья не прошла — сбоит туннель
     * раздающего телефона, а не этот телефон и не его сеть.
     */
    RELAY_UPSTREAM_FAILED(FailureKind.HEALTH_CHECK_FAILED, Severity.ERROR),

    /**
     * Сервер не принял ClientHello по частям (D-69, к D-68): с разбиением
     * рукопожатие TLS или REALITY не прошло. Та же попытка — без разбиения,
     * и до перезапуска к этому серверу — без него.
     */
    CLIENT_HELLO_SPLIT_REJECTED(FailureKind.TLS_HANDSHAKE_FAILED, Severity.WARNING),

    /**
     * Проверке сети (D-60, D-79) не пустить пробы мимо туннеля: на ПК метка
     * `SO_MARK` на сокет пробы не поставилась. Проба через туннель мерила бы
     * сервер, а не сеть (D-05), — проверки нет.
     */
    NETWORK_CHECK_UNAVAILABLE(FailureKind.NETWORK_UNREACHABLE, Severity.ERROR),

    // --- активация ---
    ACTIVATION_REJECTED(FailureKind.CONFIG_VALIDATION_FAILED, Severity.ERROR),
    ROLLED_BACK_TO_LAST_KNOWN_GOOD(FailureKind.HEALTH_CHECK_FAILED, Severity.WARNING),
    NOTHING_TO_ROLL_BACK(FailureKind.HEALTH_CHECK_FAILED, Severity.ERROR),

    // --- подписки ---
    SUBSCRIPTION_FETCH_FAILED(FailureKind.SUBSCRIPTION_FETCH_FAILED, Severity.ERROR),
    SUBSCRIPTION_EMPTY(FailureKind.SUBSCRIPTION_INVALID, Severity.ERROR),
    SUBSCRIPTION_TOO_LARGE(FailureKind.SUBSCRIPTION_INVALID, Severity.ERROR),
    SUBSCRIPTION_FORMAT_UNKNOWN(FailureKind.SUBSCRIPTION_INVALID, Severity.ERROR),
    SUBSCRIPTION_NO_USABLE_SERVERS(FailureKind.SUBSCRIPTION_INVALID, Severity.ERROR),
    SUBSCRIPTION_UNCHANGED(FailureKind.SUBSCRIPTION_INVALID, Severity.INFO),
    SUBSCRIPTION_ENTRY_SKIPPED(FailureKind.SUBSCRIPTION_INVALID, Severity.WARNING),
    SUBSCRIPTION_DIRECTIVE_IGNORED(FailureKind.SUBSCRIPTION_INVALID, Severity.WARNING),
    SUBSCRIPTION_METADATA_INVALID(FailureKind.SUBSCRIPTION_INVALID, Severity.WARNING),
    SHARE_LINK_INVALID(FailureKind.SUBSCRIPTION_INVALID, Severity.ERROR),
    SHARE_LINK_SCHEME_UNSUPPORTED(FailureKind.SUBSCRIPTION_INVALID, Severity.WARNING),
    SHARE_LINK_PARAM_UNSUPPORTED(FailureKind.SUBSCRIPTION_INVALID, Severity.WARNING),

    /**
     * Параметр ссылки отброшен: проверено по исходникам закреплённого ядра,
     * что на соединение он не влияет (D-48). Только поимённо, с находкой.
     */
    SHARE_LINK_PARAM_IGNORED(FailureKind.SUBSCRIPTION_INVALID, Severity.INFO),

    /**
     * Поставщик не отдаёт серверы без идентификатора устройства
     * (`x-hwid-not-supported`, лимит устройств Remnawave): в ответе —
     * заглушка. Идентификатор подписки включает только пользователь (D-33).
     */
    SUBSCRIPTION_DEVICE_ID_REQUIRED(FailureKind.SUBSCRIPTION_FETCH_FAILED, Severity.ERROR),

    /** Лимит устройств у поставщика исчерпан (`x-hwid-max-devices-reached`): удалить устройство у поставщика (D-33). */
    SUBSCRIPTION_DEVICE_LIMIT_REACHED(FailureKind.SUBSCRIPTION_FETCH_FAILED, Severity.ERROR),

    /** На картинке не найден читаемый QR-код (D-65): нет кода, он обрезан, размыт или пуст. */
    IMPORT_QR_NOT_FOUND(FailureKind.SUBSCRIPTION_INVALID, Severity.ERROR),

    /** Картинку не прочитать: не изображение, повреждена или больше предела (D-65). */
    IMPORT_IMAGE_UNREADABLE(FailureKind.SUBSCRIPTION_INVALID, Severity.ERROR),

    // --- хранение ---
    STORAGE_READ_FAILED(FailureKind.STORAGE_FAILED, Severity.ERROR),
    STORAGE_WRITE_FAILED(FailureKind.STORAGE_FAILED, Severity.ERROR),
    STORAGE_CORRUPTED(FailureKind.STORAGE_FAILED, Severity.ERROR),
    STORAGE_KEY_INVALID(FailureKind.STORAGE_FAILED, Severity.ERROR),

    /** Ключ данных хранилища сейчас недоступен (сбой Keystore, ввода-вывода): ничего не записано, повторить позже. */
    STORAGE_DATA_KEY_UNAVAILABLE(FailureKind.STORAGE_FAILED, Severity.ERROR),

    /** Ключ данных утрачен или не расшифровывается: сохранённое не прочитать, нужен сброс хранилища (D-19). */
    STORAGE_DATA_KEY_LOST(FailureKind.STORAGE_FAILED, Severity.ERROR),

    INTERNAL_ERROR(FailureKind.INTERNAL, Severity.ERROR),
}
