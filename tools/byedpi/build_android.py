#!/usr/bin/env python3
"""Build immutable original ByeDPI 0.17.3 using Android NDK clang."""
import argparse
import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
from android_auth import patch

REPO = "https://github.com/hufrea/byedpi.git"
COMMIT = "7efde1b1296eaaa187b70e951894dde17527489c"
ROOT = Path(__file__).resolve().parents[2]
TARGETS = {"arm64-v8a": "aarch64-linux-android", "armeabi-v7a": "armv7a-linux-androideabi",
           "x86_64": "x86_64-linux-android"}
SOURCES = ["packets.c", "main.c", "conev.c", "proxy.c", "desync.c", "mpool.c", "extend.c"]

def run(args, **kwargs):
    return subprocess.run(args, check=True, **kwargs)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--ndk", required=True, type=Path)
    parser.add_argument("--abis", default="arm64-v8a")
    a = parser.parse_args()
    llvm = a.ndk / "toolchains/llvm/prebuilt/linux-x86_64/bin"
    abis = a.abis.split(",")
    if any(x not in TARGETS for x in abis):
        raise ValueError("Unknown ABI")
    with tempfile.TemporaryDirectory() as tmp:
        src = Path(tmp)
        run(["git", "init", "-q", str(src)])
        run(["git", "-C", str(src), "fetch", "--depth=1", REPO, COMMIT])
        run(["git", "-C", str(src), "checkout", "--detach", "FETCH_HEAD"])
        actual = subprocess.check_output(["git", "-C", str(src), "rev-parse", "HEAD"], text=True).strip()
        if actual != COMMIT:
            raise ValueError("Unexpected ByeDPI source commit")
        patch(src / "proxy.c")
        assets = ROOT / "app/src/main/assets/byedpi"
        assets.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(src / "LICENSE", assets / "LICENSE.txt")
        entries = ["source=https://github.com/hufrea/byedpi/tree/" + COMMIT, "patch=DPpass local SOCKS authentication"]
        for abi in abis:
            out = ROOT / "app/src/main/jniLibs" / abi / "libciadpi.so"
            out.parent.mkdir(parents=True, exist_ok=True)
            cc = llvm / (TARGETS[abi] + "26-clang")
            run([str(cc), "-D_DEFAULT_SOURCE", "-D_GNU_SOURCE", "-std=c99", "-O2", "-fPIE",
                 "-pie", "-Wl,-z,max-page-size=16384", "-Wl,-z,common-page-size=16384",
                 "-I.", *SOURCES, "-o", str(out)], cwd=src)
            run([str(llvm / "llvm-strip"), "--strip-all", str(out)])
            entries.append(abi + "=" + hashlib.sha256(out.read_bytes()).hexdigest())
        (assets / "SOURCE.txt").write_text("\n".join(entries) + "\n", encoding="utf-8")

if __name__ == "__main__":
    main()
