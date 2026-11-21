#!/usr/bin/env python3
"""Vendor immutable Zapret2 v1.0.7 Android NFQUEUE executables and Lua runtime.

Only known archive members are extracted after the whole archive's SHA-256 is checked.
Invoke from GitHub Actions before Gradle, or manually for offline Gradle builds.
"""
import hashlib
import io
from pathlib import Path, PurePosixPath
import tarfile
import urllib.request

URL = "https://github.com/bol-van/zapret2/releases/download/v1.0.7/zapret2-v1.0.7.tar.gz"
EXPECTED = "547a5dce3f4820721a425680ea3f7f3971b7e9c772b8c795dd2d623148da0928"
OUT = Path(__file__).resolve().parents[2] / "app/src/main/assets/zapret2"
ARCH = {"android-arm64": "arm64-v8a", "android-arm": "armeabi-v7a", "android-x86_64": "x86_64"}
LUA = {"zapret-lib.lua", "zapret-antidpi.lua", "zapret-auto.lua", "zapret-obfs.lua"}

def destination(name):
    parts = PurePosixPath(name).parts
    if len(parts) >= 3 and parts[-3] == "binaries" and parts[-2] in ARCH and parts[-1] == "nfqws2":
        return ARCH[parts[-2]] + "/nfqws2"
    if len(parts) >= 2 and parts[-2] == "lua" and parts[-1] in LUA:
        return "lua/" + parts[-1]
    if len(parts) >= 2 and parts[-2] == "docs" and parts[-1] == "LICENSE.txt":
        return "LICENSE.txt"
    return None

def main():
    req = urllib.request.Request(URL, headers={"User-Agent": "DPpass-Zapret2-PinnedVendor/1.0"})
    with urllib.request.urlopen(req, timeout=90) as response:
        payload = response.read(24_000_000)
    digest = hashlib.sha256(payload).hexdigest()
    if digest != EXPECTED:
        raise ValueError("Zapret2 archive SHA-256 mismatch: " + digest)
    selected = {}
    with tarfile.open(fileobj=io.BytesIO(payload), mode="r:gz") as archive:
        for member in archive:
            target = destination(member.name)
            if target is None:
                continue
            if target in selected or not member.isfile() or member.size > 12_000_000:
                raise ValueError("Bad duplicate, type or size: " + member.name)
            selected[target] = archive.extractfile(member).read()
    required = {abi + "/nfqws2" for abi in ARCH.values()} | {"lua/" + f for f in LUA} | {"LICENSE.txt"}
    if set(selected) != required:
        raise ValueError("Missing Zapret2 assets: " + str(sorted(required - set(selected))))
    for relpath, data in selected.items():
        if relpath.endswith("/nfqws2") and not data.startswith(b"\x7fELF"):
            raise ValueError("Not an ELF: " + relpath)
        destination_path = OUT / relpath
        destination_path.parent.mkdir(parents=True, exist_ok=True)
        destination_path.write_bytes(data)
    (OUT / "MANIFEST.sha256").write_text(
        "".join(hashlib.sha256(data).hexdigest() + "  " + relpath + "\n" for relpath, data in sorted(selected.items())),
        encoding="utf-8")
    print("Pinned Zapret2 v1.0.7 assets verified:", len(selected))

if __name__ == "__main__":
    main()
