#!/usr/bin/env python3
"""Verify all checked Zapret2 upstream assets are physically present in each APK."""
import hashlib
from pathlib import Path
import sys
import zipfile

ROOT = Path(__file__).resolve().parents[2]
MANIFEST = ROOT / "app/src/main/assets/zapret2/MANIFEST.sha256"


def main():
    if len(sys.argv) != 2:
        raise SystemExit("usage: python3 check_apk_assets.py APK_DIRECTORY")
    output = Path(sys.argv[1])
    lines = MANIFEST.read_text(encoding="utf-8").splitlines()
    expected = {}
    for line in lines:
        digest, relpath = line.split("  ", 1)
        if len(digest) != 64 or relpath in expected or ".." in Path(relpath).parts:
            raise ValueError("bad vendor manifest row: " + line)
        expected["assets/zapret2/" + relpath] = digest
    if len(expected) != 8:
        raise ValueError("expected eight licensed/upstream assets, got " + str(len(expected)))
    apks = list(output.glob("*.apk"))
    if len(apks) != 3:
        raise ValueError("expected one signed APK for each of three ABIs; found " + str(len(apks)))
    for apk in sorted(apks):
        with zipfile.ZipFile(apk) as archive:
            names = set(archive.namelist())
            missing = set(expected).difference(names)
            if missing:
                raise ValueError(f"{apk.name}: missing upstream assets: {sorted(missing)}")
            for name, digest in expected.items():
                actual = hashlib.sha256(archive.read(name)).hexdigest()
                if actual != digest:
                    raise ValueError(f"{apk.name}: SHA256 mismatch on {name}")
        print(f"Verified {apk.name}: {len(expected)} vendored Zapret2 assets")


if __name__ == "__main__":
    main()
