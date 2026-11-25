#!/usr/bin/env python3
"""Check each bundled ROOT helper's ELF architecture, PIE and digest."""
import hashlib
import struct
import sys
from zipfile import ZipFile

ABIS = {"arm64-v8a": (2, 183), "armeabi-v7a": (1, 40), "x86_64": (2, 62)}

with ZipFile(sys.argv[1]) as apk:
    for abi, (elf_class, machine) in ABIS.items():
        prefix = f"assets/root-pidfd/{abi}/"
        data = apk.read(prefix + "helper.bin")
        digest = apk.read(prefix + "helper.sha256")
        assert digest == (hashlib.sha256(data).hexdigest() + "\n").encode("ascii"), abi
        assert data[:4] == b"\x7fELF" and data[4:6] == bytes([elf_class, 1]), abi
        assert struct.unpack_from("<HH", data, 16) == (3, machine), abi
        # PIE must have a program interpreter and 16 KiB-aligned load segments.
        if elf_class == 2:
            phoff = struct.unpack_from("<Q", data, 32)[0]
            entsize, count = struct.unpack_from("<HH", data, 54)
            alignment_offset, alignment_type = 48, "<Q"
        else:
            phoff = struct.unpack_from("<I", data, 28)[0]
            entsize, count = struct.unpack_from("<HH", data, 42)
            alignment_offset, alignment_type = 28, "<I"
        kinds = []
        for i in range(count):
            entry = phoff + i * entsize
            kind = struct.unpack_from("<I", data, entry)[0]
            kinds.append(kind)
            if kind == 1:
                assert struct.unpack_from(alignment_type, data, entry + alignment_offset)[0] >= 16384, abi
        assert 1 in kinds and 3 in kinds, abi
print("Verified ROOT pidfd helpers for all three Android ABIs")
