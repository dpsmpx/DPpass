#!/usr/bin/env python3
"""Check opt-in APK packaging against the ordinary debug build."""
import sys
from pathlib import Path
from zipfile import ZipFile

root = Path(__file__).resolve().parent
lib = "lib/arm64-v8a/libdppassxray.so"
license_name = "assets/localdpi/LICENSE.txt"
source_name = "assets/localdpi/SOURCE.txt"
with ZipFile(sys.argv[1]) as baseline, ZipFile(sys.argv[2]) as native:
    assert license_name not in baseline.namelist()
    assert source_name not in baseline.namelist()
    assert native.read(license_name) == (root / "vendor/byedpi/LICENSE").read_bytes()
    assert native.read(source_name) == (root / "notice-assets/localdpi/SOURCE.txt").read_bytes()
    assert native.read(lib).startswith(b"\x7fELF")
    assert native.read(lib) != baseline.read(lib), "opt-in library unchanged"
    for name in ("lib/arm64-v8a/libciadpi.so", "assets/alpine/zapret2-runtime.bin"):
        assert native.read(name) == baseline.read(name), "reference component changed"
print("Verified separate native local DPI debug APK and MIT provenance")
