#!/usr/bin/env python3
"""Сборка для автора из пакета оболочки Linux (D-74): архив, PKGBUILD с его суммой, SHA256SUMS.

    python3 tools/desktop/package.py ARCHIVE OUT_DIR

ARCHIVE — `desktop/build/distributions/dppass-desktop-<версия>.tar`
(`./gradlew :desktop:distTar`). В OUT_DIR кладутся архив, сжатый gzip
(`.tar.gz`, без даты и имени внутри — сумма воспроизводится), PKGBUILD (из
`desktop/package/PKGBUILD.in`: версия и SHA-256 сжатого архива) и SHA256SUMS.
Состав архива сверяется с тем, что ставит PKGBUILD: недостающий файл — отказ,
а не пакет, который не установится.

Код возврата: 0 — готово; 1 — архив не тот; 2 — неверный вызов.
"""
import gzip
import hashlib
import os
import re
import shutil
import sys
import tarfile

PROJ = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
TEMPLATE = os.path.join(PROJ, "desktop", "package", "PKGBUILD.in")
NAME = re.compile(r"^dppass-desktop-([0-9][0-9A-Za-z.]*(?:-[0-9A-Za-z.]+)?)\.tar$")
# То, что ставит PKGBUILD.in (относительно каталога пакета в архиве).
REQUIRED = [
    "bin/dppass-desktop", "native/libdppassxray.so", "geodata/manifest.json", "geodata/NOTICE.txt", "LICENSE",
    "package/dppass-launch", "package/dppass", "package/com.dpsmpx.dppass.policy", "package/dppass.desktop", "package/dppass.svg",
]


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def main(argv):
    if len(argv) != 2:
        print(__doc__.strip().splitlines()[2].strip(), file=sys.stderr)
        return 2
    archive, out = argv
    m = NAME.match(os.path.basename(archive))
    if not m:
        print(f"✗ {archive}: имя не dppass-desktop-<версия>.tar", file=sys.stderr)
        return 1
    version = m.group(1)
    top = f"dppass-desktop-{version}"
    with tarfile.open(archive) as t:
        names = set(t.getnames())
    missing = [f for f in REQUIRED if f"{top}/{f}" not in names]
    if missing:
        print(f"✗ {archive}: нет {', '.join(missing)} в {top}/", file=sys.stderr)
        return 1
    os.makedirs(out, exist_ok=True)
    target = os.path.join(out, os.path.basename(archive) + ".gz")
    with open(archive, "rb") as src, open(target, "wb") as raw:
        with gzip.GzipFile(filename="", mode="wb", compresslevel=9, fileobj=raw, mtime=0) as gz:
            shutil.copyfileobj(src, gz, 1 << 20)
    digest = sha256(target)
    # pkgver в Arch — без «-»: 0.1.0-dev → 0.1.0dev (младше 0.1.0, как и должно быть).
    with open(TEMPLATE, encoding="utf-8") as f:
        pkgbuild = f.read().replace("@VERSION@", version).replace("@PKGVER@", version.replace("-", "")).replace("@SHA256@", digest)
    if "@" in re.sub(r"#.*", "", pkgbuild):
        print("✗ PKGBUILD.in: осталась неподставленная метка", file=sys.stderr)
        return 1
    with open(os.path.join(out, "PKGBUILD"), "w", encoding="utf-8") as f:
        f.write(pkgbuild)
    files = sorted({os.path.basename(target), "PKGBUILD"})
    with open(os.path.join(out, "SHA256SUMS"), "w", encoding="utf-8") as f:
        for name in files:
            f.write(f"{sha256(os.path.join(out, name))}  {name}\n")
    print(f"✓ {out}: {os.path.basename(target)} ({digest[:16]}…), PKGBUILD {version}, SHA256SUMS")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
