#!/usr/bin/env python3
"""Validate the actual packaged native candidate, not just its asset names."""
import argparse
import hashlib
import re
import struct
import subprocess
import tempfile
from pathlib import Path
from zipfile import ZipFile

ROOT = Path(__file__).resolve().parent
MODULE = "github.com/dpsmpx/dppass/tools/xray"
LIB = "lib/arm64-v8a/libdppassxray.so"
LICENSE = "assets/localdpi/LICENSE.txt"
SOURCE = "assets/localdpi/SOURCE.txt"
REFERENCE = ("lib/arm64-v8a/libciadpi.so", "assets/alpine/zapret2-runtime.bin")


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def read_unique(apk, name):
    matches = [entry for entry in apk.infolist() if entry.filename == name]
    require(len(matches) == 1, f"expected exactly one ZIP entry: {name}")
    require(not matches[0].is_dir(), f"not a file: {name}")
    return apk.read(matches[0])


def check_elf(data):
    require(len(data) >= 64 and data[:6] == b"\x7fELF\x02\x01",
            "expected little-endian ELF64 JNI library")
    require(struct.unpack_from("<HH", data, 16) == (3, 183),
            "expected ARM64 shared object")


def parse_go_build_info(info, native):
    """Go embeds build settings even when symbols and build ID are stripped."""
    rows = info.splitlines()
    require(bool(rows) and ": go" in rows[0], "missing Go build info")
    settings = {}
    paths = []
    modules = []
    for row in rows[1:]:
        parts = row.strip().split("\t")
        if parts[0] == "path" and len(parts) == 2:
            paths.append(parts[1])
        elif parts[0] == "mod" and len(parts) >= 2:
            modules.append(parts[1])
        elif parts[0] == "build" and len(parts) == 2:
            key, separator, value = parts[1].partition("=")
            require(bool(separator) and key not in settings, "invalid/duplicate Go build setting")
            settings[key] = value
    require(paths == [MODULE + "/jni"] and modules == [MODULE],
            "unexpected Go main package/module")
    for key, expected in {
        "-buildmode": "c-shared",
        "CGO_ENABLED": "1",
        "GOOS": "android",
        "GOARCH": "arm64",
    }.items():
        require(settings.get(key) == expected, f"unexpected Go build setting: {key}")
    tags = set(re.split(r"[,\s]+", settings.get("-tags", "").strip('"')))
    require(("localdpi_native" in tags) == native,
            "localdpi_native build tag does not match candidate role")


def check_go_library(data, native):
    check_elf(data)
    with tempfile.TemporaryDirectory(prefix="dppass-elf-") as directory:
        path = Path(directory) / "jni.so"
        path.write_bytes(data)
        result = subprocess.run(["go", "version", "-m", str(path)],
                                check=True, capture_output=True, text=True, timeout=30)
        parse_go_build_info(result.stdout, native)


def check_apks(baseline_path, native_path, inspect=check_go_library):
    with ZipFile(baseline_path) as baseline, ZipFile(native_path) as native:
        for name in (LICENSE, SOURCE):
            require(name not in baseline.namelist(), "native notice present in baseline")
        require(read_unique(native, LICENSE) == (ROOT / "vendor/byedpi/LICENSE").read_bytes(),
                "native license differs from pinned source")
        require(read_unique(native, SOURCE) == (ROOT / "notice-assets/localdpi/SOURCE.txt").read_bytes(),
                "native source notice differs")
        baseline_lib = read_unique(baseline, LIB)
        native_lib = read_unique(native, LIB)
        require(native_lib != baseline_lib, "opt-in library unchanged")
        inspect(baseline_lib, False)
        inspect(native_lib, True)
        for name in REFERENCE:
            require(read_unique(native, name) == read_unique(baseline, name),
                    f"reference component changed: {name}")
    return sha256(native_lib)


def write_manifest(path, commit, apk_path, library_digest):
    require(re.fullmatch(r"[0-9a-f]{40}", commit) is not None, "invalid commit SHA")
    require(re.fullmatch(r"[0-9a-f]{64}", library_digest) is not None, "invalid library SHA-256")
    # Do not include local paths, signing secrets, or a physical PASS claim.
    digest = hashlib.file_digest
    with apk_path.open("rb") as apk:
        apk_digest = digest(apk, "sha256").hexdigest()
    path.write_text(
        f"commit={commit}\n"
        "native_localdpi=enabled\n"
        "applicationId=com.dpsmpx.dppass\n"
        f"apk_sha256={apk_digest}\n"
        f"jni_sha256={library_digest}\n"
        "go_build_tag=localdpi_native\n"
        "physical_acceptance=pending\n",
        encoding="ascii",
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("baseline", type=Path)
    parser.add_argument("candidate", type=Path)
    parser.add_argument("--commit")
    parser.add_argument("--manifest", type=Path)
    args = parser.parse_args()
    if bool(args.commit) != bool(args.manifest):
        parser.error("--commit and --manifest must be supplied together")
    library_digest = check_apks(args.baseline, args.candidate)
    if args.manifest is not None:
        write_manifest(args.manifest, args.commit, args.candidate, library_digest)
    print("Verified native local DPI candidate APK, actual Go build settings and MIT provenance")


if __name__ == "__main__":
    main()
