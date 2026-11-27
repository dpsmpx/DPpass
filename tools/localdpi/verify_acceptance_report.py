#!/usr/bin/env python3
"""Compare a combined DPTS local report with a trusted CI manifest offline."""
import argparse
import re
import sys
from pathlib import Path

MAX_INPUT = 64 * 1024
SHA256 = re.compile(r"[0-9a-f]{64}")
COMMIT = re.compile(r"[0-9a-f]{40}")
CASES = [
    ("HTTP / plain", 0),
    ("HTTP / http-hostcase", 1),
    ("HTTP / http-hostows", 1),
    *[(f"TLS {version} / {method}", int(method != "plain"))
      for version in ("1.2", "1.3")
      for method in ("plain", "multisplit", "tlsrec-split")],
]
MANIFEST_KEYS = {
    "commit", "native_localdpi", "applicationId", "apk_sha256",
    "jni_sha256", "go_build_tag", "physical_acceptance",
}
BUILD_KEYS = {
    "version", "split_count", "base_apk_sha256", "apk_arm64_jni_sha256",
    "single_apk_identity", "physical_network_acceptance",
}


def read_text(path):
    with path.open("rb") as stream:
        raw = stream.read(MAX_INPUT + 1)
    if len(raw) > MAX_INPUT:
        raise ValueError("input exceeds 64 KiB")
    return raw.decode("utf-8-sig")


def fields(parts, expected):
    result = {}
    for part in parts:
        key, sep, value = part.strip().partition("=")
        if not sep or key not in expected or key in result or not value:
            raise ValueError("unexpected or duplicate field")
        result[key] = value
    if result.keys() != expected:
        raise ValueError("missing fields")
    return result


def one(lines, prefix):
    matches = [line for line in lines if line.startswith(prefix)]
    if len(matches) != 1:
        raise ValueError("missing or duplicate " + prefix.strip())
    return matches[0]


def manifest_fields(text):
    m = fields(text.splitlines(), MANIFEST_KEYS)
    if (not COMMIT.fullmatch(m["commit"]) or
            not SHA256.fullmatch(m["apk_sha256"]) or
            not SHA256.fullmatch(m["jni_sha256"])):
        raise ValueError("invalid candidate digest")
    if (m["native_localdpi"] != "enabled" or
            m["applicationId"] != "com.dpsmpx.dppass" or
            m["go_build_tag"] != "localdpi_native" or
            m["physical_acceptance"] != "pending"):
        raise ValueError("unexpected candidate manifest role")
    return m


def verify(manifest, report):
    """Return (matched, reason); malformed or ambiguous input raises ValueError."""
    m = manifest_fields(manifest)
    lines = report.splitlines()
    if not lines or lines[0] != "=== DPpass local HTTP/TLS self-test ===":
        return False, "combined_acceptance_report_required"
    if any(line.startswith("===") for line in lines[1:]):
        raise ValueError("multiple report headers")
    build_line = one(lines, "BUILD: ")
    if build_line == "BUILD: identity_unavailable":
        return False, "build_identity_unavailable"
    b = fields(build_line[len("BUILD: "):].split(";"), BUILD_KEYS)
    if not re.fullmatch(r"[A-Za-z0-9._+\-]{1,80}", b["version"]):
        raise ValueError("invalid build version")
    if (b["split_count"] != "0" or b["single_apk_identity"] != "true" or
            b["physical_network_acceptance"] != "not_measured"):
        return False, "single_apk_identity_required"
    if (b["base_apk_sha256"] != m["apk_sha256"] or
            b["apk_arm64_jni_sha256"] != m["jni_sha256"]):
        return False, "candidate_digest_mismatch"
    if one(lines, "RUN: ") != "RUN: completed; training_eligible=false":
        return False, "run_not_completed"
    if one(lines, "Executed: ") != "Executed: 9/9; missing=0; extra=0":
        return False, "incomplete_case_count"
    if one(lines, "budget_ms=") != "budget_ms=45000":
        return False, "unexpected_case_budget"
    # The report is a sequential finite fixture, not an unordered set.
    rows = [line for line in lines if re.match(r"^(HTTP|TLS [^:]+) / ", line)]
    if len(rows) != len(CASES):
        return False, "unexpected_case_rows"
    for row, (label, applied) in zip(rows, CASES):
        prefix = f"{label}: verified; applied={applied}; skipped=0; elapsed_ms="
        if not row.startswith(prefix) or not re.fullmatch(r"[0-9]{1,8}", row[len(prefix):]):
            return False, "case_not_verified"
    for prefix, expected in (
        ("Verified: ", "Verified: 9/9"),
        ("HTTP: ", "HTTP: 3/3"),
        ("TLS 1.2: ", "TLS 1.2: 3/3"),
        ("TLS 1.3: ", "TLS 1.3: 3/3"),
        ("ACCEPTANCE: ", "ACCEPTANCE: PASS"),
    ):
        if one(lines, prefix) != expected:
            return False, "aggregate_not_verified"
    return True, "reported_local_fixtures_match_candidate"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", type=Path)
    parser.add_argument("report", type=Path)
    args = parser.parse_args()
    try:
        matched, reason = verify(read_text(args.manifest), read_text(args.report))
    except (OSError, UnicodeError, ValueError):
        print("REPORT_INVALID: malformed, ambiguous or unreadable input")
        return 2
    print(("LOCAL_REPORT_MATCH" if matched else "LOCAL_REPORT_NOT_VERIFIED") + ": " + reason)
    print("physical_network_acceptance=not_measured; text_authenticity=not_verified")
    return 0 if matched else 1


if __name__ == "__main__":
    sys.exit(main())
