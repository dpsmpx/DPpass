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
        (tools/release/dppass-sign-termux.sh): файла ключа в сессии нет

Ключ — только из окружения (D-35), в командную строку пароли не попадают
(`apksigner … --ks-pass env:…`):

    DPPASS_SIGNING_KEYSTORE_BASE64  хранилище PKCS12 в base64
      или DPPASS_SIGNING_KEYSTORE   путь к нему
    DPPASS_SIGNING_STORE_PASSWORD   пароль хранилища
    DPPASS_SIGNING_KEY_ALIAS        алиас ключа (dppass-dev)
    DPPASS_SIGNING_KEY_PASSWORD     пароль ключа

Без ключа сборка не подписывается вовсе: отладочный ключ контейнера
молча не подставляется — APK с ним не встал бы поверх установленного.

Личность пакета (D-47, D-49): случайные на вид `applicationId` и ярлык, но
постоянные для ключа — зерно `dppass.identitySeed` выводится из отпечатка
сертификата и пароля хранилища (без пароля его не вычислить). Тот же ключ —
тот же пакет: следующая сборка ставится поверх прежней. Пакет APK сверяется
с ожидаемым (повтор `AppIdentity` на Python).

Шаги: `:app:assembleRelease -Pdppass.abiSplit=true` (APK на ABI, D-28) →
выравнивание zip (4 байта, библиотеки — 16 КБ) → `apksigner sign` →
`apksigner verify`: подпись v2/v3 и сертификат = отпечаток из
docs/PROVENANCE.md, §7 → `check_apk.py --abi --release` (R8 и договор JNI,
D-91) → SHA256SUMS.

Без подписи (`--unsigned`): файл ключа не нужен, нужен только пароль
хранилища (`DPPASS_SIGNING_STORE_PASSWORD`; алиас — `DPPASS_SIGNING_KEY_ALIAS`,
по умолчанию `dppass-dev`). Зерно личности — из отпечатка, записанного в
docs/PROVENANCE.md, §7, и этого пароля; шаги те же, кроме подписи. Рядом
с APK — `dppass-sign-termux.sh`: на устройстве он сверяет пароль с
зерном сборки (`seed-sha256` в CERTIFICATE.txt — иначе пакет не тот),
подписывает APK ключом автора и сверяет сертификат с отпечатком.

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
TERMUX_SIGNER = os.path.join(PROJ, "tools", "release", "dppass-sign-termux.sh")
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


def identity_seed(cert_sha256):
    """Зерно личности пакета (D-49): постоянное для ключа и пароля, без пароля не вычисляется."""
    material = f"dppass-identity:{cert_sha256}:{os.environ[ENV_STORE_PASS]}"
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


APP_IDENTITY = os.path.join(PROJ, "build-logic", "src", "main", "kotlin", "com", "dpsmpx", "dppass", "build", "AppIdentity.kt")


class JavaRandom:
    """java.util.Random: та же последовательность, что у AppIdentity.random (Kotlin)."""

    def __init__(self, seed):
        self.s = (seed ^ 0x5DEECE66D) & ((1 << 48) - 1)

    def next(self, bits):
        self.s = (self.s * 0x5DEECE66D + 0xB) & ((1 << 48) - 1)
        return self.s >> (48 - bits)

    def next_int(self, bound):
        r, m = self.next(31), bound - 1
        if bound & m == 0:
            return (bound * r) >> 31
        u = r
        while True:
            r = u % bound
            if u - r + m <= 0x7FFFFFFF:
                return r
            u = self.next(31)


def expected_identity(seed):
    """(applicationId, ярлык) по зерну — повтор AppIdentity.seedOf и AppIdentity.random; списки — из исходника."""
    src = read_text(APP_IDENTITY)
    labels = re.findall(r'"([A-Z][a-z]+)"', re.search(r"LABELS = listOf\((.*?)\)", src, re.S).group(1))
    cons = re.search(r'CONSONANTS = "([a-z]+)"', src).group(1)
    vow = re.search(r'VOWELS = "([a-z]+)"', src).group(1)
    h = 1125899906842597
    for c in seed:
        h = (31 * h + ord(c)) & ((1 << 64) - 1)
    rnd = JavaRandom(h)

    def segment():
        n = 5 + rnd.next_int(4)
        return "".join((cons if i % 2 == 0 else vow)[rnd.next_int(len(cons if i % 2 == 0 else vow))] for i in range(n))

    app = "com." + segment() + "." + segment()
    return app, labels[rnd.next_int(len(labels))]


def read_text(path):
    with open(path, encoding="utf-8") as f:
        return f.read()


def package_of(tools, apk):
    """Имя пакета и ярлык APK (`aapt2 dump badging`)."""
    out = run([os.path.join(tools, "aapt2"), "dump", "badging", apk], "aapt2 dump badging")
    name = re.search(r"^package: name='([^']+)'", out, re.M)
    label = re.search(r"^application-label:'([^']*)'", out, re.M)
    return (name.group(1) if name else None), (label.group(1) if label else None)


def version_name():
    with open(GRADLE_APP, encoding="utf-8") as f:
        m = re.search(r'versionName\s*=\s*"([^"]+)"', f.read())
    if not m:
        fail("в app/build.gradle.kts нет versionName")
    if not m.group(1).endswith("-dev"):
        fail(f"versionName {m.group(1)}: тестовая сборка — только с суффиксом -dev (D-35)")
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
    a.add_argument("--unsigned", action="store_true",
                   help="без подписи: личность — из записанного отпечатка и пароля, подпись — на устройстве автора")
    args = a.parse_args()
    tmp = tempfile.mkdtemp(prefix="dppass-sign-")
    try:
        if args.unsigned:
            if not os.environ.get(ENV_STORE_PASS):
                fail(f"нет {ENV_STORE_PASS}: без пароля хранилища не вычислить личность пакета (D-49)")
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
            expected = recorded(alias)
            if actual != expected:
                fail(f"ключ из окружения ({actual}) — не тот, что записан в docs/PROVENANCE.md, §7 ({expected})")
        version = version_name()
        seed = identity_seed(expected)
        want = expected_identity(seed)
        sdk = sdk_dir()
        tools = build_tools(sdk) if sdk else None
        if not tools or not all(os.path.isfile(os.path.join(tools, t)) for t in ("apksigner", "zipalign")):
            fail("нет build-tools Android SDK с apksigner и zipalign (ANDROID_HOME)")

        if not args.skip_build:
            # Без кеша конфигурации: личность считается при конфигурации, и кеш отдал бы
            # прежнюю (6 октября 2026: переменная окружения до Gradle не дошла, а кеш
            # закрепил случайную личность — поэтому зерно через -P и пакет сверяется ниже).
            gradle = [os.path.join(PROJ, "gradlew"), "--quiet", "--no-configuration-cache", "-p", PROJ,
                      ":app:assembleRelease", "-Pdppass.abiSplit=true"]
            print("… " + " ".join(gradle[4:]) + " -Pdppass.identitySeed=…", flush=True)
            subprocess.run(gradle + [f"-Pdppass.identitySeed={seed}"], check=True)
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
            problems.append(f"у APK разные пакеты: {sorted(packages)} — сборка по ABI должна дать один пакет (D-49)")
        elif packages and next(iter(packages)) != want:
            problems.append(f"пакет APK {next(iter(packages))} ≠ ожидаемому для ключа {want} — личность не из зерна ключа "
                            "(кеш конфигурации, свойство не дошло до Gradle?), D-49")
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
            f.write(f"# Ключ {alias}: SHA-256 сертификата — docs/PROVENANCE.md, §7; пакет и ярлык постоянны для ключа (D-49).\n")
            if args.unsigned:
                f.write("# APK не подписаны: подписывает автор (dppass-sign-termux.sh). seed-sha256 — SHA-256 зерна\n"
                        "# личности: по нему скрипт проверяет, что пароль тот же, что при сборке.\n")
            f.write(f"alias: {alias}\ncertificate-sha256: {expected}\npackage: {package}\nlabel: {label}\n")
            if args.unsigned:
                f.write(f"seed-sha256: {hashlib.sha256(seed.encode('ascii')).hexdigest()}\n")
        if args.unsigned:
            shutil.copy(TERMUX_SIGNER, os.path.join(args.out, os.path.basename(TERMUX_SIGNER)))
            print(f"✓ {len(made)} APK ({version}, {rev}) без подписи, личность ключа {alias} ({expected[:16]}…), "
                  f"check_apk.py --abi --release пройден; пакет {package} «{label}»; подписать на устройстве — "
                  f"{os.path.basename(TERMUX_SIGNER)}: {os.path.relpath(args.out, PROJ)}")
            return 0
        print(f"✓ {len(made)} APK ({version}, {rev}) подписаны ключом {alias} ({expected[:16]}…), "
              f"сертификат сверен с docs/PROVENANCE.md, §7, check_apk.py --abi --release пройден; пакет {package} «{label}»: "
              f"{os.path.relpath(args.out, PROJ)}")
        return 0
    except Refusal as e:
        print(f"✗ sign_apks: {e}")
        return 2
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
