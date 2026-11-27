#!/usr/bin/env python3
"""Host tests of native APK verification; no Android SDK or private signing key."""
import hashlib
import importlib.util
import tempfile
import unittest
import warnings
from pathlib import Path
from zipfile import ZipFile

spec = importlib.util.spec_from_file_location(
    "check_debug_apk", Path(__file__).resolve().parents[1] / "check_debug_apk.py")
checker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checker)


def info(native=True):
    return "\n".join([
        "jni.so: go1.27.1",
        "\tpath\t" + checker.MODULE + "/jni",
        "\tmod\t" + checker.MODULE + "\t(devel)\t",
        "\tbuild\t-buildmode=c-shared",
        "\tbuild\tCGO_ENABLED=1",
        "\tbuild\tGOOS=android",
        "\tbuild\tGOARCH=arm64",
        "\tbuild\t-tags=localdpi_native,other" if native else "\tbuild\t-tags=other",
    ])


class CandidateCheck(unittest.TestCase):
    def test_build_info(self):
        checker.parse_go_build_info(info(), True)
        checker.parse_go_build_info(info(False), False)
        for bad in (
            "",
            info(False),
            info().replace("GOARCH=arm64", "GOARCH=amd64"),
            info().replace("GOOS=android", "GOOS=linux"),
            info().replace("CGO_ENABLED=1", "CGO_ENABLED=0"),
            info().replace("-buildmode=c-shared", "-buildmode=exe"),
            info().replace("/jni", "/other"),
            info().replace("localdpi_native,other", "not_localdpi_native"),
            info() + "\n\tbuild\tGOARCH=arm64",
        ):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                checker.parse_go_build_info(bad, True)
        with self.assertRaises(ValueError):
            checker.parse_go_build_info(info(), False)

    def test_elf(self):
        data = bytearray(64)
        data[:6] = b"\x7fELF\x02\x01"
        data[16:20] = bytes([3, 0, 183, 0])
        checker.check_elf(data)
        for index in (0, 4, 5, 16, 18):
            wrong = data.copy()
            wrong[index] ^= 1
            with self.assertRaises(ValueError):
                checker.check_elf(wrong)
        with self.assertRaises(ValueError):
            checker.check_elf(data[:63])

    def make_apk(self, path, native, change=None, duplicate=None):
        entries = {
            checker.LIB: b"native" if native else b"baseline",
            **{name: name.encode() for name in checker.REFERENCE},
        }
        if native:
            entries[checker.LICENSE] = (checker.ROOT / "vendor/byedpi/LICENSE").read_bytes()
            entries[checker.SOURCE] = (checker.ROOT / "notice-assets/localdpi/SOURCE.txt").read_bytes()
        if change:
            name, data = change
            if data is None:
                del entries[name]
            else:
                entries[name] = data
        with ZipFile(path, "w") as apk:
            for name, data in entries.items():
                apk.writestr(name, data)
            if duplicate:
                with warnings.catch_warnings():
                    warnings.simplefilter("ignore", UserWarning)
                    apk.writestr(duplicate, entries[duplicate])

    def test_packaged_candidate(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            baseline, candidate = root / "base.apk", root / "candidate.apk"
            self.make_apk(baseline, False)
            self.make_apk(candidate, True)
            calls = []
            digest = checker.check_apks(baseline, candidate,
                                         lambda data, native: calls.append((data, native)))
            self.assertEqual(calls, [(b"baseline", False), (b"native", True)])
            self.assertEqual(digest, hashlib.sha256(b"native").hexdigest())
            manifest = root / "NATIVE_CANDIDATE.txt"
            checker.write_manifest(manifest, "a" * 40, candidate, digest)
            self.assertIn("apk_sha256=" + hashlib.sha256(candidate.read_bytes()).hexdigest(),
                          manifest.read_text())
            self.assertIn("jni_sha256=" + digest, manifest.read_text())
            self.assertIn("physical_acceptance=pending", manifest.read_text())
            with self.assertRaises(ValueError):
                checker.write_manifest(manifest, "bad", candidate, digest)

            for change in ((checker.LIB, b"baseline"), (checker.LICENSE, b"wrong"),
                           (checker.SOURCE, None), (checker.REFERENCE[0], b"wrong"),
                           (checker.REFERENCE[1], None)):
                self.make_apk(candidate, True, change=change)
                with self.subTest(change=change), self.assertRaises(ValueError):
                    checker.check_apks(baseline, candidate, lambda *_: None)
            for name in (checker.LIB, checker.LICENSE, checker.SOURCE, *checker.REFERENCE):
                self.make_apk(candidate, True, duplicate=name)
                with self.subTest(duplicate=name), self.assertRaises(ValueError):
                    checker.check_apks(baseline, candidate, lambda *_: None)
            self.make_apk(candidate, True)
            self.make_apk(baseline, False, change=(checker.LICENSE, b"wrong"))
            with self.assertRaises(ValueError):
                checker.check_apks(baseline, candidate, lambda *_: None)


if __name__ == "__main__":
    unittest.main()
