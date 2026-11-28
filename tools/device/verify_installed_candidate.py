#!/usr/bin/env python3
"""Read-only verification of an installed DPpass prerelease against trusted CI files."""
import argparse
import hashlib
import re
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "localdpi"))
from verify_acceptance_report import manifest_fields, read_text, verify as verify_report

PACKAGE = "com.dpsmpx.dppass"
PIN = "c18792812566ca4a18b518d51313515ff2d62bf8299446e99943eeb5d0630d11"
JNI = "lib/arm64-v8a/libdppassxray.so"
MAX_APK = 512 * 1024 * 1024
MAX_JNI = 128 * 1024 * 1024
BASE = re.compile(r"/data/app/[A-Za-z0-9_+=~./-]+/base\.apk")
VERSION = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+-(?:rc|alpha)\.[0-9]+")


class Mismatch(Exception):
    """The evidence disagrees with the expected candidate."""


def require(condition, reason):
    if not condition:
        raise Mismatch(reason)


def parse_version(text):
    rows = text.splitlines()
    if (len(rows) != 2 or not re.fullmatch(r"[1-9][0-9]{0,9}", rows[0])
            or int(rows[0]) > 2147483647 or not VERSION.fullmatch(rows[1])):
        raise ValueError("invalid update version file")
    return int(rows[0]), rows[1]


def run(args, timeout=30):
    return subprocess.run(args, check=True, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, text=True, timeout=timeout).stdout


def base_path(output):
    lines = output.splitlines()
    require(len(lines) == 1 and lines[0].startswith("package:"), "single_base_apk_required")
    path = lines[0][len("package:"):]
    require(BASE.fullmatch(path) is not None and all(part not in (".", "..", "") for part in path[1:].split("/")),
            "unexpected_base_apk_path")
    return path


def apk_size(output):
    value = output.strip()
    if not re.fullmatch(r"[1-9][0-9]{0,9}", value):
        raise ValueError("invalid size from adb")
    size = int(value)
    require(size <= MAX_APK, "apk_size_limit")
    return size


def hash_stream(stream, limit):
    digest = hashlib.sha256()
    total = 0
    while True:
        chunk = stream.read(1024 * 1024)
        if not chunk:
            return digest.hexdigest(), total
        total += len(chunk)
        require(total <= limit, "file_size_limit")
        digest.update(chunk)


def check_signer(output):
    rows = [line for line in output.splitlines()
            if re.match(r"Signer #[0-9]+ certificate SHA-256 digest:", line)]
    require(rows == ["Signer #1 certificate SHA-256 digest: " + PIN], "signer_mismatch")


def check_badging(output, code, name):
    rows = [line for line in output.splitlines() if line.startswith("package: ")]
    require(len(rows) == 1, "package_metadata_missing")
    match = re.match(r"package: name='([^']+)' versionCode='([0-9]+)' versionName='([^']+)'(?: |$)", rows[0])
    require(match is not None and match.groups() == (PACKAGE, str(code), name), "package_or_version_mismatch")


def verify(manifest, version, adb="adb", apksigner="apksigner", aapt="aapt", serial=None, command=run, report=None):
    m = manifest_fields(manifest)
    code, name = parse_version(version)
    if report is not None:
        matched, reason = verify_report(manifest, report, expected_version=name)
        require(matched, reason)
    # Resolve once: never let later adb calls silently select another device.
    if serial is None:
        serial = command([adb, "get-serialno"]).strip()
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:\[\]%-]{0,255}", serial) or serial == "unknown":
        raise ValueError("invalid adb device selection")
    prefix = [adb, "-s", serial]
    if command(prefix + ["get-state"]).strip() != "device":
        raise ValueError("adb device unavailable")

    def installed_path():
        return base_path(command(prefix + ["shell", "pm", "path", PACKAGE]))

    path = installed_path()
    size = apk_size(command(prefix + ["shell", "stat", "-c", "%s", path]))
    with tempfile.TemporaryDirectory(prefix="dppass-candidate-") as directory:
        apk = Path(directory) / "candidate.apk"
        command(prefix + ["pull", path, str(apk)], timeout=180)
        require(apk.is_file() and apk.stat().st_size == size, "installed_apk_size_changed")
        require(installed_path() == path, "installed_package_changed")
        with apk.open("rb") as stream:
            digest, total = hash_stream(stream, MAX_APK)
        require(total == size and digest == m["apk_sha256"], "apk_digest_mismatch")
        with zipfile.ZipFile(apk) as archive:
            matches = [entry for entry in archive.infolist() if entry.filename == JNI]
            require(len(matches) == 1 and not matches[0].is_dir()
                    and 0 < matches[0].file_size <= MAX_JNI, "arm64_jni_missing_or_ambiguous")
            with archive.open(matches[0]) as stream:
                digest, total = hash_stream(stream, MAX_JNI)
            require(total == matches[0].file_size and digest == m["jni_sha256"], "jni_digest_mismatch")
        check_signer(command([apksigner, "verify", "--print-certs", str(apk)]))
        check_badging(command([aapt, "dump", "badging", str(apk)]), code, name)
        require(installed_path() == path, "installed_package_changed")
    return code, name


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", type=Path)
    parser.add_argument("version", type=Path)
    parser.add_argument("--report", type=Path, help="also verify the combined local DPTS report")
    parser.add_argument("--serial")
    parser.add_argument("--adb", default="adb")
    parser.add_argument("--apksigner", default="apksigner")
    parser.add_argument("--aapt", default="aapt")
    args = parser.parse_args()
    try:
        code, name = verify(read_text(args.manifest), read_text(args.version),
                            args.adb, args.apksigner, args.aapt, args.serial,
                            report=read_text(args.report) if args.report else None)
    except Mismatch as exc:
        print("INSTALLED_CANDIDATE_MISMATCH: " + str(exc))
        return 1
    except (OSError, ValueError, subprocess.SubprocessError, zipfile.BadZipFile):
        print("INSTALLED_CANDIDATE_ERROR: invalid input, unavailable device or tool failure")
        return 2
    print(f"INSTALLED_CANDIDATE_MATCH: version={name}; versionCode={code}")
    if args.report:
        print("LOCAL_REPORT_MATCH: reported_local_fixtures_match_candidate; text_authenticity=not_verified")
    print("physical_network_acceptance=not_measured; updater_origin=not_verified; subscription_preservation=not_verified")
    return 0


if __name__ == "__main__":
    sys.exit(main())
