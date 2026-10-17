#!/usr/bin/env bash
# Суммы SHA-256 артефактов, которые берёт Gradle (gradle/verification-metadata.xml):
# подменённый артефакт той же версии сборка не примет (T10, аудит A-7).
#
#   ANDROID_HOME=… tools/provenance/update_verification.sh
#
# Файл пересоздаётся целиком — версии, которых сборка больше не берёт, не
# остаются доверенными. Задачи — те же, что у полного прогона hostcheck, и
# сборка release по ABI (tools/release/sign_apks.py): что не разрешилось при
# генерации, потом не пройдёт проверку. Без Android SDK в суммы не войдут
# зависимости app — поэтому без ANDROID_HOME скрипт не работает.
# Разницу файла просмотреть: новые суммы — только у новых версий (D-18).
set -euo pipefail
cd "$(dirname "$0")/../.."

if [ -z "${ANDROID_HOME:-}" ] || [ ! -d "$ANDROID_HOME" ]; then
  echo "✗ нужен ANDROID_HOME: без Android SDK в суммы не войдут зависимости app"
  exit 2
fi

# Настройки проверки — до генерации: Gradle сохраняет раздел configuration.
# Только SHA-256 (подписей PGP у части артефактов Google Maven нет);
# javadoc и исходники доверены без сумм — их скачивает IDE, сборка — нет.
cat > gradle/verification-metadata.xml <<'XML'
<?xml version="1.0" encoding="UTF-8"?>
<verification-metadata xmlns="https://schema.gradle.org/dependency-verification" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:schemaLocation="https://schema.gradle.org/dependency-verification https://schema.gradle.org/dependency-verification/dependency-verification-1.3.xsd">
   <configuration>
      <verify-metadata>true</verify-metadata>
      <verify-signatures>false</verify-signatures>
      <trusted-artifacts>
         <trust file=".*-javadoc[.]jar" regex="true"/>
         <trust file=".*-sources[.]jar" regex="true"/>
      </trusted-artifacts>
   </configuration>
   <components>
   </components>
</verification-metadata>
XML

./gradlew --console=plain --warning-mode=summary --write-verification-metadata sha256 \
  build :build-logic:test ktlintCheck :app:lint :app:assembleRelease -Pdppass.abiSplit=true
python3 tools/provenance/check_dependencies.py
