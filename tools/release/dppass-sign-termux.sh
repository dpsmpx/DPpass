#!/data/data/com.termux/files/usr/bin/bash
# DPpass — подпись тестовых APK ключом dppass-dev на устройстве автора (D-35, D-49).
#
# Сборка без подписи (tools/release/sign_apks.py --unsigned) кладёт рядом с
# APK этот скрипт, SHA256SUMS и CERTIFICATE.txt. Запускать в Termux в каталоге,
# куда они скачаны (например, после termux-setup-storage: cd ~/storage/downloads):
#
#     bash dppass-sign-termux.sh
#
# Что делает:
#   1. сверяет скачанные APK с SHA256SUMS (APK других ABI можно не скачивать);
#   2. спрашивает пароль ключа и сверяет его с зерном сборки (seed-sha256 в
#      CERTIFICATE.txt): с другим паролем у сборки другое имя пакета, и
#      следующая сборка не встала бы поверх (D-49);
#   3. подписывает каждый *-unsigned.apk ключом ~/dppass-keys/dppass-dev.p12
#      (другой путь — переменная DPPASS_KEYSTORE), не трогая выравнивание
#      библиотек по 16 КБ;
#   4. сверяет сертификат подписи с отпечатком из CERTIFICATE.txt
#      (docs/PROVENANCE.md, §7).
# Пароль не попадает ни в командную строку, ни в файлы.
set -eu

KS="${DPPASS_KEYSTORE:-$HOME/dppass-keys/dppass-dev.p12}"
CERT=CERTIFICATE.txt

field() { sed -n "s/^$1: //p" "$CERT" | head -n 1; }

[ -f "$CERT" ] || { echo "✗ нет $CERT рядом с APK: скачайте его из той же ветки"; exit 2; }
[ -f "$KS" ] || { echo "✗ нет ключа $KS (создаёт dppass-keygen-termux.sh; другой путь — DPPASS_KEYSTORE)"; exit 2; }
ALIAS="$(field alias)"
FP="$(field certificate-sha256)"
CHECK="$(field seed-sha256)"
PACKAGE="$(field package)"
[ -n "$ALIAS" ] && [ -n "$FP" ] && [ -n "$CHECK" ] || { echo "✗ $CERT — не от сборки без подписи (нет alias, certificate-sha256 или seed-sha256)"; exit 2; }

shopt -s nullglob
APKS=(*-unsigned.apk)
[ "${#APKS[@]}" -gt 0 ] || { echo "✗ в $(pwd) нет *-unsigned.apk"; exit 2; }

if [ -f SHA256SUMS ]; then
  sha256sum -c --ignore-missing SHA256SUMS || { echo "✗ APK не совпал с SHA256SUMS: скачайте заново"; exit 1; }
else
  echo "! нет SHA256SUMS — целостность скачанных APK не проверена"
fi

if ! command -v apksigner >/dev/null 2>&1; then
  echo ">> Ставлю apksigner…"
  pkg install -y apksigner
fi
# Новые apksigner сами выравнивают библиотеки по 16 КБ, старые — по 4 КБ:
# сборка уже выровнена (zipalign -P 16), поэтому выравнивание сохраняется.
KEEP=()
if apksigner sign --help 2>&1 | grep -q -- '--alignment-preserved'; then
  KEEP=(--alignment-preserved true)
else
  echo "! этот apksigner не умеет --alignment-preserved: выравнивание библиотек — на его усмотрение"
fi

read -r -s -p "Пароль ключа $ALIAS: " DPPASS_SIGN_PASSWORD
echo
SEED="$(printf '%s' "dppass-identity:$FP:$DPPASS_SIGN_PASSWORD" | sha256sum | cut -d' ' -f1)"
if [ "$(printf '%s' "$SEED" | sha256sum | cut -d' ' -f1)" != "$CHECK" ]; then
  unset DPPASS_SIGN_PASSWORD SEED
  echo "✗ пароль не тот, с которым собрана сборка: имя пакета не совпало бы с прежними сборками (D-49). Ничего не подписано."
  exit 1
fi
unset SEED
export DPPASS_SIGN_PASSWORD

status=0
for u in "${APKS[@]}"; do
  out="${u%-unsigned.apk}.apk"
  rm -f "$out" "$out.idsig"
  if ! apksigner sign --ks "$KS" --ks-type PKCS12 --ks-key-alias "$ALIAS" \
      --ks-pass env:DPPASS_SIGN_PASSWORD --key-pass env:DPPASS_SIGN_PASSWORD \
      "${KEEP[@]}" --out "$out" "$u"; then
    echo "✗ $u: apksigner не подписал"
    status=1
    continue
  fi
  # Строка сертификата: «Signer #1 certificate SHA-256 digest: …» (apksigner до 36) или
  # «V3.0 Signer: certificate SHA-256 digest: …» (37.0.0). Ровно один сертификат — ключа автора.
  got="$(apksigner verify --print-certs "$out" \
    | sed -n -E 's/^(Signer #[0-9]+|V[0-9.]+ Signer):? certificate SHA-256 digest: ([0-9a-f]{64})$/\2/p' | sort -u)"
  if [ "$got" != "$FP" ]; then
    echo "✗ $out: сертификат $got ≠ $FP — файл удалён"
    rm -f "$out"
    status=1
    continue
  fi
  # Подпись v4 (.idsig) нужна только установке через adb по частям.
  rm -f "$out.idsig"
  echo "✓ $out — подписан $ALIAS, сертификат ${FP:0:16}…, пакет $PACKAGE"
done
unset DPPASS_SIGN_PASSWORD
[ "$status" -eq 0 ] && echo ">> Установить: откройте .apk (без -unsigned) в файловом менеджере или termux-open <файл>.apk"
exit "$status"
