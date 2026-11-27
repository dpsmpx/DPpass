#!/usr/bin/env python3
import importlib.util
import tempfile
import unittest
from pathlib import Path

spec = importlib.util.spec_from_file_location(
    "verify_acceptance_report", Path(__file__).resolve().parents[1] / "verify_acceptance_report.py")
v = importlib.util.module_from_spec(spec)
spec.loader.exec_module(v)

MANIFEST = "\n".join([
    "commit=" + "a" * 40, "native_localdpi=enabled",
    "applicationId=com.dpsmpx.dppass", "apk_sha256=" + "b" * 64,
    "jni_sha256=" + "c" * 64, "go_build_tag=localdpi_native",
    "physical_acceptance=pending",
])
ROWS = [
    f"{label}: verified; applied={applied}; skipped=0; elapsed_ms=10"
    for label, applied in v.CASES
]
REPORT = "\n".join([
    "=== DPpass local HTTP/TLS self-test ===",
    "BUILD: version=0.8.3-rc.7-dev; split_count=0; base_apk_sha256=" + "b" * 64 +
    "; apk_arm64_jni_sha256=" + "c" * 64 +
    "; single_apk_identity=true; physical_network_acceptance=not_measured",
    "budget_ms=45000", "RUN: completed; training_eligible=false",
    "Executed: 9/9; missing=0; extra=0", *ROWS,
    "Verified: 9/9", "HTTP: 3/3", "TLS 1.2: 3/3", "TLS 1.3: 3/3",
    "ACCEPTANCE: PASS",
])


class VerifyAcceptance(unittest.TestCase):
    def test_match(self):
        self.assertTrue(v.verify(MANIFEST, REPORT)[0])
        self.assertTrue(v.verify(MANIFEST + "\n", REPORT.replace("\n", "\r\n"))[0])

    def test_nonmatching_reports(self):
        for before, after in (
            ("b" * 64, "d" * 64), ("c" * 64, "d" * 64),
            ("split_count=0", "split_count=1"),
            ("single_apk_identity=true", "single_apk_identity=false"),
            ("RUN: completed", "RUN: interrupted; reason=user_stop"),
            ("Executed: 9/9; missing=0; extra=0", "Executed: 8/9; missing=1; extra=0"),
            ("budget_ms=45000", "budget_ms=5000"),
            (ROWS[0], ROWS[0].replace("applied=0", "applied=1")),
            (ROWS[1], ROWS[1].replace("skipped=0", "skipped=1")),
            (ROWS[2], ROWS[2].replace("verified", "local_http_mismatch / unconfirmed")),
            (ROWS[3], ROWS[3].replace("elapsed_ms=10", "elapsed_ms=-1")),
            (ROWS[4] + "\n" + ROWS[5], ROWS[5] + "\n" + ROWS[4]),
            (ROWS[6], ROWS[6] + "\n" + ROWS[6]),
            (ROWS[7] + "\n", ""),
            ("Verified: 9/9", "Verified: 8/9"),
            ("HTTP: 3/3", "HTTP: 2/3"),
            ("ACCEPTANCE: PASS", "ACCEPTANCE: NOT_VERIFIED"),
        ):
            with self.subTest(before=before, after=after):
                self.assertFalse(v.verify(MANIFEST, REPORT.replace(before, after, 1))[0])

    def test_ambiguous_or_malformed(self):
        for bad in (
            MANIFEST + "\napk_sha256=" + "b" * 64,
            MANIFEST.replace("commit=" + "a" * 40, "commit=bad"),
            MANIFEST.replace("physical_acceptance=pending", "physical_acceptance=pass"),
        ):
            with self.assertRaises(ValueError):
                v.verify(bad, REPORT)
        for bad in (
            REPORT + "\nACCEPTANCE: PASS",
            REPORT + "\n" + REPORT,
            REPORT.replace("split_count=0", "split_count=0; split_count=0"),
        ):
            with self.assertRaises(ValueError):
                v.verify(MANIFEST, bad)

    def test_bounded_input(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "report.txt"
            path.write_bytes(b"\xef\xbb\xbf" + REPORT.encode())
            self.assertEqual(v.read_text(path), REPORT)
            path.write_bytes(b"x" * (v.MAX_INPUT + 1))
            with self.assertRaises(ValueError):
                v.read_text(path)


if __name__ == "__main__":
    unittest.main()
