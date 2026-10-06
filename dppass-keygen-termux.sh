#!/data/data/com.termux/files/usr/bin/bash
# DPpass — личный ключ подписи dppass-dev (D-35). Запускать в Termux.
# Ключ создаётся ТОЛЬКО у вас. В репозиторий он не попадает (D-35).
# ВАЖНО: сохраните и файл .p12, и пароль в менеджер паролей —
# без них нельзя будет обновить установленное приложение «поверх».
set -eu

echo ">> Ставлю OpenJDK (keytool)…"
pkg install -y openjdk-17 >/dev/null 2>&1 || pkg install -y openjdk-17

umask 077
mkdir -p "$HOME/dppass-keys"
cd "$HOME/dppass-keys"

if [ -f dppass-dev.p12 ]; then
  echo "!! Уже есть $HOME/dppass-keys/dppass-dev.p12 — НЕ перезаписываю."
  echo "   Если хотите новый ключ, сначала сохраните старый в другое место и удалите этот файл."
  exit 1
fi

# Надёжный пароль 24 символа (буквы+цифры).
PW="$(LC_ALL=C tr -dc 'A-Za-z0-9' </dev/urandom | head -c 24)"

echo ">> Генерирую RSA 4096, PKCS12, алиас dppass-dev…"
keytool -genkeypair -alias dppass-dev -keyalg RSA -keysize 4096 -validity 10000 \
  -storetype PKCS12 -keystore dppass-dev.p12 \
  -storepass "$PW" -keypass "$PW" \
  -dname "CN=DPpass Dev, O=DPpass, OU=personal" >/dev/null

chmod 600 dppass-dev.p12
base64 -w0 dppass-dev.p12 > dppass-dev.p12.b64
chmod 600 dppass-dev.p12.b64

FP="$(keytool -list -v -keystore dppass-dev.p12 -storepass "$PW" -alias dppass-dev 2>/dev/null \
      | awk -F': ' '/SHA256:/{gsub(/:/,"",$2); print tolower($2); exit}')"

echo
echo "================= СОХРАНИТЕ В МЕНЕДЖЕР ПАРОЛЕЙ (показывается один раз) ================="
echo "Пароль хранилища и ключа:"
echo "    $PW"
echo "Файл ключа:        $HOME/dppass-keys/dppass-dev.p12   (НЕ ТЕРЯТЬ)"
echo "Отпечаток SHA-256 сертификата (для PROVENANCE §7, сверит sign_apks.py):"
echo "    $FP"
echo
echo "================= ВСТАВИТЬ В СЕКРЕТЫ ОКРУЖЕНИЯ (Edit → Secrets) ================="
echo "DPPASS_SIGNING_KEY_ALIAS        = dppass-dev"
echo "DPPASS_SIGNING_STORE_PASSWORD   = $PW"
echo "DPPASS_SIGNING_KEY_PASSWORD     = $PW"
echo "DPPASS_SIGNING_KEYSTORE_BASE64  = одна длинная строка из команды ниже:"
echo
echo "    cat ~/dppass-keys/dppass-dev.p12.b64 ; echo"
echo
echo ">> Готово. Рекомендация: скопируйте dppass-dev.p12 и пароль в менеджер паролей"
echo "   или зашифрованный бэкап. Это ваш единственный ключ для обновлений приложения."
