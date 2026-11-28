#!/usr/bin/env python3
import hashlib
import io
from pathlib import Path
import subprocess
import unittest
import zipfile

import verify_installed_candidate as v


def fixture():
    jni = b"local synthetic JNI fixture"
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr(v.JNI, jni)
    raw = buffer.getvalue()
    manifest = "\n".join([
        "commit=" + "a" * 40,
        "native_localdpi=enabled",
        "applicationId=" + v.PACKAGE,
        "apk_sha256=" + hashlib.sha256(raw).hexdigest(),
        "jni_sha256=" + hashlib.sha256(jni).hexdigest(),
        "go_build_tag=localdpi_native",
        "physical_acceptance=pending",
    ])
    return raw, manifest


class FakeDevice:
    path = "/data/app/~~aB9_=/com.dpsmpx.dppass-XyZ/base.apk"

    def __init__(self, raw):
        self.raw = raw
        self.paths = [self.path] * 3
        self.signer = "Signer #1 certificate SHA-256 digest: " + v.PIN
        self.badging = "package: name='com.dpsmpx.dppass' versionCode='165' versionName='0.8.3-rc.9'"
        self.size = len(raw)
        self.calls = []
        self.local = None

    def __call__(self, args, timeout=30):
        self.calls.append(args)
        cmd = args[3:] if args[1:3] == ["-s", "test-device"] else args[1:]
        if args[0] == "apksigner":
            return self.signer
        if args[0] == "aapt":
            return self.badging
        if cmd == ["get-state"]:
            return "device\n"
        if cmd == ["shell", "pm", "path", v.PACKAGE]:
            return "package:" + self.paths.pop(0) + "\n"
        if cmd == ["shell", "stat", "-c", "%s", self.path]:
            return str(self.size)
        if cmd[:2] == ["pull", self.path]:
            self.local = Path(cmd[2])
            self.local.write_bytes(self.raw)
            return ""
        raise AssertionError("unexpected command")


class VerifyInstalledTest(unittest.TestCase):
    def test_exact_candidate_and_read_only_commands(self):
        raw, manifest = fixture()
        device = FakeDevice(raw)
        self.assertEqual(v.verify(manifest, "165\n0.8.3-rc.9\n", serial="test-device", command=device),
                         (165, "0.8.3-rc.9"))
        self.assertFalse(device.local.exists())
        self.assertEqual(sum("pull" in call for call in device.calls), 1)
        self.assertFalse(any(token in call for token in ["install", "uninstall", "root", "clear", "run-as"]
                             for call in device.calls))

    def test_mismatch_paths_size_hash_signer_and_version(self):
        raw, manifest = fixture()
        for field, value, reason in [
            ("paths", [FakeDevice.path + "\npackage:/data/app/split.apk"], "single_base_apk_required"),
            ("paths", ["/data/app/../base.apk"], "unexpected_base_apk_path"),
            ("paths", [FakeDevice.path, "/data/app/new/base.apk"], "installed_package_changed"),
            ("size", v.MAX_APK + 1, "apk_size_limit"),
            ("size", len(raw) + 1, "installed_apk_size_changed"),
            ("raw", b"x" * len(raw), "apk_digest_mismatch"),
            ("signer", "Signer #1 certificate SHA-256 digest: " + "b" * 64, "signer_mismatch"),
            ("signer", "Signer #1 certificate SHA-256 digest: " + v.PIN + "\nSigner #2 certificate SHA-256 digest: " + v.PIN, "signer_mismatch"),
            ("badging", "package: name='com.example.other' versionCode='165' versionName='0.8.3-rc.9'", "package_or_version_mismatch"),
        ]:
            with self.subTest(field=field, reason=reason):
                device = FakeDevice(raw)
                setattr(device, field, value)
                with self.assertRaisesRegex(v.Mismatch, reason):
                    v.verify(manifest, "165\n0.8.3-rc.9\n", command=device)
                if device.local is not None:
                    self.assertFalse(device.local.exists())

    def test_jni_digest_mismatch(self):
        raw, manifest = fixture()
        manifest = "\n".join("jni_sha256=" + "b" * 64 if line.startswith("jni_sha256=") else line
                             for line in manifest.splitlines())
        with self.assertRaisesRegex(v.Mismatch, "jni_digest_mismatch"):
            v.verify(manifest, "165\n0.8.3-rc.9\n", command=FakeDevice(raw))

    def test_invalid_metadata_before_adb(self):
        raw, manifest = fixture()
        for text in ("0\n0.8.3-rc.9", "165\nwrong", "165\n0.8.3-rc.9\nextra", "2147483648\n0.8.3-rc.9"):
            device = FakeDevice(raw)
            with self.assertRaises(ValueError):
                v.verify(manifest, text, command=device)
            self.assertEqual(device.calls, [])

    def test_bounded_stream_and_command_failure(self):
        with self.assertRaisesRegex(v.Mismatch, "file_size_limit"):
            v.hash_stream(io.BytesIO(b"12345"), 4)
        raw, manifest = fixture()
        def fail(args, timeout=30):
            raise subprocess.TimeoutExpired(args, timeout)
        with self.assertRaises(subprocess.TimeoutExpired):
            v.verify(manifest, "165\n0.8.3-rc.9\n", command=fail)


if __name__ == "__main__":
    unittest.main()
