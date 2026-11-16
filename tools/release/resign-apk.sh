#!/bin/sh
# Переподписать APK DPpass ключом выпуска автора — на телефоне, в Termux (или
# proot Alpine), где есть apksigner (docs/PROCESS.md, «Тестовые сборки», п. 3).
# Ключ и пароли не покидают телефон: путь, псевдоним и пароли — свойства
# dppass.release.* из ~/.gradle/gradle.properties; пароли идут в apksigner через
# окружение (env:…), не через командную строку и не в вывод.
#
#   sh resign-apk.sh dppass-<версия>-<код>-<abi>-unsigned.apk …
#
# Рядом с каждым APK — <имя>-author.apk (у «…-unsigned.apk» суффикс заменяется
# на «-author.apk»). Сертификат подписи (SHA-256, SHA-1) печатается; если в
# свойствах есть dppass.release.certSha256 (полный хеш или его начало), он
# сверяется: не тот ключ — отказ, файл удаляется.
#
# ~/.gradle/gradle.properties (пример; без storeFile берётся
# ~/dppass_keys/dppass-release.jks):
#   dppass.release.storeFile=/data/data/com.termux/files/home/dppass_keys/dppass-release.jks
#   dppass.release.keyAlias=<псевдоним ключа>
#   dppass.release.storePassword=<пароль хранилища>
#   dppass.release.keyPassword=<пароль ключа>
#   dppass.release.certSha256=<необязательно: SHA-256 сертификата>
#
# Хранилище — JKS или PKCS#12 (.p12, .pfx): тип определяет apksigner по файлу,
# для .p12/.pfx он задаётся явно. Если есть только dppass-release.jks.b64
# (base64 хранилища), скрипт один раз раскодирует его рядом в .jks.
#
# Переменные: DPPASS_GRADLE_PROPERTIES — другой файл свойств; APKSIGNER — путь
# к apksigner, если его нет в PATH и в $ANDROID_HOME/build-tools.
#
# Выравнивание библиотек (zipalign -P 16, D-28) сохраняется: сборка уже
# выровнена, apksigner её не трогает. Подпись — v2 и v3, без v1: minSdk 26, а
# JAR-подпись добавила бы в APK файлы META-INF — содержимое должно остаться
# ровно тем, что собрано. Имя пакета у сборки — com.dpsmpx.dppass (D-114) и
# от ключа не зависит.
set -eu

PROPS=${DPPASS_GRADLE_PROPERTIES:-$HOME/.gradle/gradle.properties}
if [ ! -f "$PROPS" ]; then
    echo "✗ нет $PROPS: в нём — dppass.release.keyAlias, storePassword, keyPassword (и storeFile, если ключ не в ~/dppass_keys/dppass-release.jks)" >&2
    exit 2
fi
prop() { sed -n "s/^dppass\.release\.$1[[:space:]]*=[[:space:]]*//p" "$PROPS" | head -n 1 | tr -d '\r'; }
STORE=$(prop storeFile)
[ -n "$STORE" ] || STORE="$HOME/dppass_keys/dppass-release.jks"
ALIAS=$(prop keyAlias)
EXPECT=$(prop certSha256 | tr -d ': ' | tr 'A-F' 'a-f')
DPPASS_KS_PASS=$(prop storePassword)
DPPASS_KEY_PASS=$(prop keyPassword)
if [ -z "$ALIAS" ] || [ -z "$DPPASS_KS_PASS" ] || [ -z "$DPPASS_KEY_PASS" ]; then
    echo "✗ в $PROPS нет одного из dppass.release.keyAlias, storePassword, keyPassword" >&2
    exit 2
fi
if [ ! -f "$STORE" ] && [ -f "$STORE.b64" ]; then
    # Только base64-копия хранилища: раскодировать рядом, права — только владельцу.
    ( umask 077 && base64 -d "$STORE.b64" > "$STORE" ) || { rm -f "$STORE"; echo "✗ не удалось раскодировать $STORE.b64" >&2; exit 2; }
    echo "… хранилище раскодировано из $STORE.b64 в $STORE"
fi
if [ ! -f "$STORE" ]; then
    echo "✗ нет хранилища ключа $STORE (dppass.release.storeFile)" >&2
    exit 2
fi
export DPPASS_KS_PASS DPPASS_KEY_PASS

signer() {
    if [ -n "${APKSIGNER:-}" ]; then echo "$APKSIGNER"; return 0; fi
    if command -v apksigner >/dev/null 2>&1; then command -v apksigner; return 0; fi
    for sdk in "${ANDROID_HOME:-}" "${ANDROID_SDK_ROOT:-}" "$HOME/android-sdk" "$HOME/Android/Sdk"; do
        [ -n "$sdk" ] || continue
        last=$(ls -d "$sdk"/build-tools/*/apksigner 2>/dev/null | tail -n 1)
        if [ -n "$last" ]; then echo "$last"; return 0; fi
    done
    return 1
}
SIGNER=$(signer) || {
    echo "✗ нет apksigner: в Termux — pkg install apksigner; или APKSIGNER=<путь>" >&2
    exit 2
}

# PKCS#12 (.p12, .pfx) — явно: apksigner по умолчанию ждёт тип хранилища JVM.
case "$STORE" in
    *.p12 | *.pfx | *.P12 | *.PFX) KS_TYPE="--ks-type PKCS12" ;;
    *) KS_TYPE="" ;;
esac

# Новые apksigner сами выравнивают библиотеки по 16 КБ, старые — по 4 КБ:
# сборка уже выровнена (zipalign -P 16), поэтому выравнивание сохраняется.
KEEP=""
if "$SIGNER" sign --help 2>&1 | grep -q -- '--alignment-preserved'; then
    KEEP="--alignment-preserved true"
else
    echo "! этот apksigner не умеет --alignment-preserved: выравнивание библиотек — на его усмотрение" >&2
fi

[ "$#" -gt 0 ] || { echo "sh resign-apk.sh <файл.apk>…" >&2; exit 2; }
for apk in "$@"; do
    [ -f "$apk" ] || { echo "✗ нет файла $apk" >&2; exit 2; }
done

# Целостность скачанного: если рядом SHA256SUMS от сборки — сверить.
dir=$(dirname "$apk")
if [ -f "$dir/SHA256SUMS" ]; then
    ( cd "$dir" && sha256sum -c --ignore-missing SHA256SUMS ) >/dev/null 2>&1 \
        || { echo "✗ APK не совпал с SHA256SUMS: скачайте заново" >&2; exit 1; }
fi

status=0
for apk in "$@"; do
    case "$apk" in
        *-unsigned.apk) out="${apk%-unsigned.apk}-author.apk" ;;
        *) out="${apk%.apk}-author.apk" ;;
    esac
    rm -f "$out" "$out.idsig"
    # shellcheck disable=SC2086 # KS_TYPE и KEEP — несколько слов или пусто.
    "$SIGNER" sign --ks "$STORE" $KS_TYPE --ks-key-alias "$ALIAS" \
        --ks-pass env:DPPASS_KS_PASS --key-pass env:DPPASS_KEY_PASS \
        $KEEP --v1-signing-enabled false --v2-signing-enabled true --v3-signing-enabled true \
        --out "$out" "$apk" || { echo "✗ $apk: apksigner не подписал" >&2; status=1; continue; }
    certs=$("$SIGNER" verify --print-certs "$out")
    sha256=$(printf '%s\n' "$certs" | sed -n -E 's/^(Signer #[0-9]+|V[0-9.]+ Signer):? certificate SHA-256 digest: //p' | sort -u | head -n 1)
    sha1=$(printf '%s\n' "$certs" | sed -n -E 's/^(Signer #[0-9]+|V[0-9.]+ Signer):? certificate SHA-1 digest: //p' | sort -u | head -n 1)
    if [ -n "$EXPECT" ]; then
        case "$sha256" in
            "$EXPECT"*) ;;
            *)
                rm -f "$out" "$out.idsig"
                echo "✗ $apk: подписан сертификатом $sha256, а ждали $EXPECT (dppass.release.certSha256) — файл удалён" >&2
                status=1
                continue
                ;;
        esac
    fi
    # Подпись v4 (.idsig) нужна только установке через adb по частям.
    rm -f "$out.idsig"
    echo "✓ $out"
    echo "  сертификат SHA-256: $sha256"
    echo "  сертификат SHA-1:   $sha1"
    echo "  файл SHA-256:       $(sha256sum "$out" | cut -d ' ' -f 1)"
done
[ "$status" -eq 0 ] && echo ">> Установить: откройте *-author.apk в файловом менеджере или termux-open <файл>-author.apk"
exit "$status"
