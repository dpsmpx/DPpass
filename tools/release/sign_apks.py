#!/usr/bin/env python3
"""Тестовые сборки для устройств автора (D-35): APK на каждый ABI, подписанные ключом разработчика.

Это не выпуск (`CLAUDE.md`, «Чего не делать»: выпуск — этап 5): сборка
`release` без R8, версия с `-dev`, ключ разработчика, а не ключ магазинов.

    python3 tools/release/sign_apks.py [--out DIR] [--skip-build]
        APK в DIR (по умолчанию build/release-apk) с SHA256SUMS и CERTIFICATE.txt
    python3 tools/release/sign_apks.py --fingerprint
        отпечаток сертификата ключа из окружения — для docs/PROVENANCE.md, §7
    python3 tools/release/sign_apks.py --unsigned [--out DIR]
        те же APK без подписи — подписывает автор на своём устройстве
        (tools/release/resign-apk.sh): файла ключа в сессии нет

Ключ — только из окружения (D-35), в командную строку пароли не попадают
(`apksigner … --ks-pass env:…`):

    DPPASS_SIGNING_KEYSTORE_BASE64  хранилище PKCS12 в base64
      или DPPASS_SIGNING_KEYSTORE   путь к нему
    DPPASS_SIGNING_STORE_PASSWORD   пароль хранилища
    DPPASS_SIGNING_KEY_ALIAS        алиас ключа (dppass-dev)
    DPPASS_SIGNING_KEY_PASSWORD     пароль ключа

Без ключа сборка не подписывается вовсе: отладочный ключ контейнера
молча не подставляется — APK с ним не встал бы поверх установленного.

Личность пакета (D-114): `com.dpsmpx.dppass` «DPpass» у всех сборок — не зависит
от ключа и пароля, следующая сборка ставится поверх прежней. Пакет APK сверяется
с ожидаемым. (Случайная личность D-47/D-49 — только `-Pdppass.randomIdentity=true`,
этим скриптом не собирается.)

Шаги: `:app:assembleRelease -Pdppass.abiSplit=true` (APK на ABI, D-28) →
выравнивание zip (4 байта, библиотеки — 16 КБ) → `apksigner sign` →
`apksigner verify`: подпись v2/v3 и сертификат = отпечаток из
docs/PROVENANCE.md, §7 → `check_apk.py --abi --release` (R8 и договор JNI,
D-91) → SHA256SUMS.

Без подписи (`--unsigned`): ни файл ключа, ни пароль не нужны (алиас —
`DPPASS_SIGNING_KEY_ALIAS`, по умолчанию `dppass-dev`); шаги те же, кроме
подписи. Рядом с APK — `resign-apk.sh`: на устройстве он
подписывает APK ключом автора из `dppass.release.*` и сверяет сертификат с
`dppass.release.certSha256`, если он задан.

Код возврата: 0 — APK готовы; 1 — проверка не прошла; 2 — нет ключа,
Android SDK или записанного отпечатка.
"""
import argparse
import base64
import binascii
import hashlib
import os
import re
import shutil
import subprocess
import sys
import tempfile

PROJ = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(PROJ, "tools", "hostcheck"))
from check_apk import build_tools, sdk_dir  # noqa: E402 — тот же поиск SDK, что у проверки APK

ABIS = ("arm64-v8a", "armeabi-v7a", "x86_64")
OUTPUTS = os.path.join(PROJ, "app", "build", "outputs", "apk", "release")
PROVENANCE = os.path.join(PROJ, "docs", "PROVENANCE.md")
GRADLE_APP = os.path.join(PROJ, "app", "build.gradle.kts")
ENV_KS_B64 = "DPPASS_SIGNING_KEYSTORE_BASE64"
ENV_KS = "DPPASS_SIGNING_KEYSTORE"
ENV_STORE_PASS = "DPPASS_SIGNING_STORE_PASSWORD"
ENV_ALIAS = "DPPASS_SIGNING_KEY_ALIAS"
ENV_KEY_PASS = "DPPASS_SIGNING_KEY_PASSWORD"
# Строка таблицы §7: | `dppass-dev` | <64 hex> |
RECORDED = re.compile(r"^\|\s*`([^`]+)`\s*\|\s*([0-9a-f]{64})\s*\|\s*$", re.M)
DEFAULT_ALIAS = "dppass-dev"
TERMUX_SIGNER = os.path.join(PROJ, "tools", "release", "resign-apk.sh")
# Сертификат подписанта в выводе `apksigner verify --print-certs`: до build-tools 36 —
# «Signer #1 certificate SHA-256 digest: …», в 37.0.0 — «V3.0 Signer: certificate SHA-256
# digest: …» (сборка в Termux, 17 октября 2026). Читаются оба вида.
CERT_LINE = re.compile(r"^(?:Signer #\d+|V\d+(?:\.\d+)* Signer):? certificate SHA-256 digest:\s*([0-9a-f]{64})\s*$", re.M)
SIGNER_COUNT = re.compile(r"^Number of signers:\s*(\d+)\s*$", re.M)


class Refusal(Exception):
    """Нечем подписывать или не с чем сверять — код 2."""


def fail(msg):
    raise Refusal(msg)


def keystore(tmp):
    """Путь к хранилищу: из base64 — во временный файл 0600 (удаляется вместе с каталогом)."""
    for env in (ENV_STORE_PASS, ENV_ALIAS, ENV_KEY_PASS):
        if not os.environ.get(env):
            fail(f"нет {env}: ключ разработчика берётся только из окружения (D-35)")
    raw = os.environ.get(ENV_KS_B64)
    if raw:
        try:
            data = base64.b64decode("".join(raw.split()), validate=True)
        except binascii.Error:
            fail(f"{ENV_KS_B64}: не base64")
        path = os.path.join(tmp, "dev.p12")
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(data)
        return path
    path = os.environ.get(ENV_KS)
    if not path:
        fail(f"нет {ENV_KS_B64} или {ENV_KS}: без ключа разработчика APK не подписываются (D-35)")
    if not os.path.isfile(path):
        fail(f"{ENV_KS}: файла нет")
    return path


def fingerprint(ks):
    """SHA-256 сертификата ключа (64 hex строчными) — через keytool, пароль из окружения."""
    out = subprocess.run(
        ["keytool", "-list", "-v", "-keystore", ks, "-storetype", "PKCS12",
         "-alias", os.environ[ENV_ALIAS], "-storepass:env", ENV_STORE_PASS],
        capture_output=True, text=True)
    if out.returncode != 0:
        fail(f"keytool не прочитал хранилище: {(out.stdout + out.stderr).strip().splitlines()[-1:]}")
    m = re.search(r"SHA256:\s*([0-9A-F:]{95})", out.stdout)
    if not m:
        fail("keytool не показал SHA-256 сертификата")
    return m.group(1).replace(":", "").lower()


def recorded(alias):
    with open(PROVENANCE, encoding="utf-8") as f:
        text = f.read()
    for name, digest in RECORDED.findall(text):
        if name == alias:
            return digest
    fail(f"в docs/PROVENANCE.md, §7 нет отпечатка ключа `{alias}`: запишите вывод --fingerprint "
         "(отпечаток — то, с чем автор сверяет APK)")


# Личность пакета (D-114): одна для всех сборок — не зависит ни от ключа, ни от пароля.
STABLE_IDENTITY = ("com.dpsmpx.dppass", "DPpass")


def package_of(tools, apk):
    """Имя пакета и ярлык APK (`aapt2 dump badging`)."""
    out = run([os.path.join(tools, "aapt2"), "dump", "badging", apk], "aapt2 dump badging")
    name = re.search(r"^package: name='([^']+)'", out, re.M)
    label = re.search(r"^application-label:'([^']*)'", out, re.M)
    return (name.group(1) if name else None), (label.group(1) if label else None)


def version_name(allow_prerelease=False):
    with open(GRADLE_APP, encoding="utf-8") as f:
        m = re.search(r'versionName\s*=\s*"([^"]+)"', f.read())
    if not m:
        fail("в app/build.gradle.kts нет versionName")
    version = m.group(1)
    prerelease = bool(re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+-alpha\.[0-9]+", version))
    if not version.endswith("-dev") and not (allow_prerelease and prerelease):
        fail(f"versionName {version}: непроверенный ключ — только -dev; alpha требует закреплённый сертификат")
    return m.group(1)


def revision():
    sha = subprocess.run(["git", "rev-parse", "--short=7", "HEAD"], cwd=PROJ, capture_output=True, text=True).stdout.strip()
    dirty = subprocess.run(["git", "status", "--porcelain"], cwd=PROJ, capture_output=True, text=True).stdout.strip()
    return (sha or "nogit") + ("-dirty" if dirty else "")


def run(cmd, what):
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0:
        tail = "\n    ".join((r.stdout + r.stderr).strip().splitlines()[-15:])
        raise RuntimeError(f"{what}: код {r.returncode}\n    {tail}")
    return r.stdout


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def align_only(tools, unsigned, out):
    """Без подписи: выровнять (библиотеки — 16 КБ, D-25) и проверить выравнивание; подпишет автор."""
    run([os.path.join(tools, "zipalign"), "-f", "-P", "16", "4", unsigned, out], "zipalign")
    run([os.path.join(tools, "zipalign"), "-c", "-P", "16", "4", out], "zipalign -c")
    return []


def signer_certs(verify):
    """Отпечатки сертификатов подписантов из вывода apksigner — без повторов, по порядку."""
    return list(dict.fromkeys(CERT_LINE.findall(verify)))


def certificate_problem(verify, expected):
    """Ровно один подписант с сертификатом [expected]; иначе — что показал apksigner."""
    certs = signer_certs(verify)
    count = SIGNER_COUNT.search(verify)
    if certs == [expected] and (count is None or int(count.group(1)) == 1):
        return None
    shown = [line.strip() for line in verify.splitlines() if CERT_LINE.match(line.strip())]
    signers = f", подписантов — {count.group(1)}" if count else ""
    return (f"сертификат подписи ≠ записанному в docs/PROVENANCE.md, §7 ({expected}); "
            f"apksigner: {shown or 'строки сертификата нет'}{signers}")


def sign_one(tools, ks, unsigned, out, expected):
    """Выровнять, подписать, проверить подпись и сертификат; problems — список нарушений."""
    problems = []
    aligned = out + ".aligned"
    # AGP выравнивает и сам; повтор с -P 16 гарантирует 16 КБ для библиотек (D-25).
    run([os.path.join(tools, "zipalign"), "-f", "-P", "16", "4", unsigned, aligned], "zipalign")
    try:
        run([os.path.join(tools, "apksigner"), "sign", "--ks", ks, "--ks-type", "PKCS12",
             "--ks-key-alias", os.environ[ENV_ALIAS],
             "--ks-pass", "env:" + ENV_STORE_PASS, "--key-pass", "env:" + ENV_KEY_PASS,
             "--out", out, aligned], "apksigner sign")
    finally:
        os.remove(aligned)
    verify = run([os.path.join(tools, "apksigner"), "verify", "--verbose", "--print-certs", out], "apksigner verify")
    if not re.search(r"Verified using v[23] scheme \(APK Signature Scheme v[23]\): true", verify):
        problems.append("подпись не схемы v2/v3")
    cert = certificate_problem(verify, expected)
    if cert:
        problems.append(cert)
    run([os.path.join(tools, "zipalign"), "-c", "-P", "16", "4", out], "zipalign -c после подписи")
    return problems


def main():
    a = argparse.ArgumentParser(description="Тестовые APK по ABI, подписанные ключом разработчика (D-35)")
    a.add_argument("--out", default=os.path.join(PROJ, "build", "release-apk"))
    a.add_argument("--skip-build", action="store_true", help="не собирать: взять готовые APK из app/build/outputs")
    a.add_argument("--fingerprint", action="store_true", help="напечатать отпечаток ключа из окружения и выйти")
    a.add_argument("--allow-unpinned-key", action="store_true",
                   help="только закрытый черновик: тест нового сертификата без записи в PROVENANCE")
    a.add_argument("--pinned-fingerprint", metavar="SHA256",
                   help="подписанный alpha: требовать конкретный SHA-256, уже записанный в PROVENANCE")
    a.add_argument("--unsigned", action="store_true",
                   help="без подписи: сертификат — из записанного отпечатка, подпись — на устройстве автора")
    args = a.parse_args()
    if args.allow_unpinned_key and args.pinned_fingerprint:
        a.error("--allow-unpinned-key нельзя сочетать с --pinned-fingerprint")
    if args.unsigned and args.pinned_fingerprint:
        a.error("--pinned-fingerprint требует подписи")
    tmp = tempfile.mkdtemp(prefix="dppass-sign-")
    try:
        if args.unsigned:
            alias = os.environ.get(ENV_ALIAS) or DEFAULT_ALIAS
            ks = None
            expected = recorded(alias)
        else:
            ks = keystore(tmp)
            alias = os.environ[ENV_ALIAS]
            actual = fingerprint(ks)
            if args.fingerprint:
                print(f"| `{alias}` | {actual} |")
                return 0
            if args.pinned_fingerprint:
                expected = args.pinned_fingerprint.lower()
                with open(PROVENANCE, encoding="utf-8") as provenance_file:
                    authorized = {digest for _, digest in RECORDED.findall(provenance_file.read())}
                if not re.fullmatch(r"[0-9a-f]{64}", expected) or expected not in authorized:
                    fail("зафиксированный сертификат отсутствует в docs/PROVENANCE.md, §7")
                if actual != expected:
                    fail(f"ключ GitHub Actions ({actual}) не соответствует закреплённому сертификату ({expected})")
            elif args.allow_unpinned_key:
                expected = actual
                print(f"⚠ Preflight: сертификат SHA-256 {actual}; ключ НЕ закреплён в docs/PROVENANCE.md, официальный выпуск запрещён", flush=True)
            else:
                expected = recorded(alias)
                if actual != expected:
                    fail(f"ключ из окружения ({actual}) — не тот, что записан в docs/PROVENANCE.md, §7 ({expected})")
        version = version_name(allow_prerelease=bool(args.pinned_fingerprint))
        want = STABLE_IDENTITY
        sdk = sdk_dir()
        tools = build_tools(sdk) if sdk else None
        if not tools or not all(os.path.isfile(os.path.join(tools, t)) for t in ("apksigner", "zipalign")):
            fail("нет build-tools Android SDK с apksigner и zipalign (ANDROID_HOME)")

        if not args.skip_build:
            # Без кеша конфигурации: личность считается при конфигурации; пакет сверяется ниже (D-114).
            gradle = [os.path.join(PROJ, "gradlew"), "--quiet", "--no-configuration-cache", "-p", PROJ,
                      ":app:assembleRelease", "-Pdppass.abiSplit=true"]
            print("… " + " ".join(gradle[4:]), flush=True)
            subprocess.run(gradle, check=True)
        os.makedirs(args.out, exist_ok=True)
        rev = revision()
        problems, made, packages = [], [], set()
        for abi in ABIS:
            unsigned = os.path.join(OUTPUTS, f"app-{abi}-release-unsigned.apk")
            if not os.path.isfile(unsigned):
                problems.append(f"{abi}: нет {os.path.relpath(unsigned, PROJ)}")
                continue
            name = f"dppass-{version}-{rev}-{abi}" + ("-unsigned.apk" if args.unsigned else ".apk")
            out = os.path.join(args.out, name)
            try:
                bad = align_only(tools, unsigned, out) if args.unsigned else sign_one(tools, ks, unsigned, out, expected)
            except RuntimeError as e:
                problems.append(f"{abi}: {e}")
                continue
            problems += [f"{abi}: {p}" for p in bad]
            check = subprocess.run([sys.executable, os.path.join(PROJ, "tools", "hostcheck", "check_apk.py"), out, "--abi", abi, "--release"],
                                   capture_output=True, text=True)
            if check.returncode != 0:
                problems.append(f"{abi}: check_apk.py\n    " + "\n    ".join((check.stdout + check.stderr).strip().splitlines()))
            made.append(name)
            packages.add(package_of(tools, out))
        if len(packages) > 1:
            problems.append(f"у APK разные пакеты: {sorted(packages)} — сборка по ABI должна дать один пакет (D-114)")
        elif packages and next(iter(packages)) != want:
            problems.append(f"пакет APK {next(iter(packages))} ≠ ожидаемому {want} — личность не стабильная "
                            "(кеш конфигурации, свойство dppass.randomIdentity?), D-114")
        if problems:
            print("✗ sign_apks:")
            for p in problems:
                print("    " + p)
            return 1
        with open(os.path.join(args.out, "SHA256SUMS"), "w", encoding="utf-8") as f:
            for name in made:
                f.write(f"{sha256(os.path.join(args.out, name))}  {name}\n")
        package, label = next(iter(packages))
        with open(os.path.join(args.out, "CERTIFICATE.txt"), "w", encoding="utf-8") as f:
            if args.allow_unpinned_key:
                f.write("# ПРЕДВАРИТЕЛЬНЫЙ APK: сертификат НЕ закреплён в docs/PROVENANCE.md, §7.\n")
            else:
                f.write(f"# Ключ {alias}: SHA-256 сертификата — docs/PROVENANCE.md, §7; пакет и ярлык постоянны (D-114).\n")
            if args.unsigned:
                f.write("# APK не подписаны: подписывает автор (resign-apk.sh).\n")
            f.write(f"alias: {alias}\ncertificate-sha256: {expected}\npackage: {package}\nlabel: {label}\n")
        if args.unsigned:
            shutil.copy(TERMUX_SIGNER, os.path.join(args.out, os.path.basename(TERMUX_SIGNER)))
            print(f"✓ {len(made)} APK ({version}, {rev}) без подписи, личность ключа {alias} ({expected[:16]}…), "
                  f"check_apk.py --abi --release пройден; пакет {package} «{label}»; подписать на устройстве — "
                  f"{os.path.basename(TERMUX_SIGNER)}: {os.path.relpath(args.out, PROJ)}")
            return 0
        print(f"✓ {len(made)} APK ({version}, {rev}) подписаны ключом {alias} ({expected[:16]}…), "
              f"сертификат проверен по ключу подписи" + (" (НЕ закреплён в PROVENANCE)" if args.allow_unpinned_key else " и docs/PROVENANCE.md, §7") + f", check_apk.py --abi --release пройден; пакет {package} «{label}»: "
              f"{os.path.relpath(args.out, PROJ)}")
        return 0
    except Refusal as e:
        print(f"✗ sign_apks: {e}")
        return 2
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
