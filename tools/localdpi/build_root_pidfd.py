#!/usr/bin/env python3
"""Build the dormant ROOT pidfd helper from project sources for Android."""
import argparse
import hashlib
from pathlib import Path
import subprocess
import tempfile

BASE = Path(__file__).resolve().parent
TARGETS = {
    "arm64-v8a": "aarch64-linux-android26",
    "armeabi-v7a": "armv7a-linux-androideabi26",
    "x86_64": "x86_64-linux-android26",
}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--ndk", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args()
    # Same Linux NDK host toolchain as the existing Alpine/ByeDPI build.
    llvm = args.ndk / "toolchains/llvm/prebuilt/linux-x86_64/bin"
    for abi, target in TARGETS.items():
        out = args.out / abi
        out.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=out) as tmp:
            binary = Path(tmp) / "helper.bin"
            subprocess.run([
                str(llvm / (target + "-clang")), "-std=c11", "-Wall", "-Wextra", "-Werror",
                "-DDPPASS_REQUIRE_PIDFD_SYSCALLS", "-O2", "-fPIE", "-pie",
                "-Wl,-z,max-page-size=16384", "-Wl,-z,common-page-size=16384",
                str(BASE / "root_pidfd.c"), str(BASE / "root_pidfd_cli.c"),
                "-o", str(binary),
            ], check=True)
            subprocess.run([str(llvm / "llvm-strip"), "--strip-all", str(binary)], check=True)
            data = binary.read_bytes()
            binary.replace(out / "helper.bin")
            (out / "helper.sha256").write_text(hashlib.sha256(data).hexdigest() + "\n", encoding="ascii")


if __name__ == "__main__":
    main()
