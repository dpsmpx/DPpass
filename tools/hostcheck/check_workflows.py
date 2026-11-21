#!/usr/bin/env python3
"""D-118: reject unreviewed GitHub Actions workflows rather than disabling CI.

The signed Zapret2 alpha workflow is the sole explicit exception to D-23.
Adding another workflow requires a new architectural decision and review.
"""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
WORKFLOWS = ROOT / ".github" / "workflows"
APPROVED = {"zapret2-signed-preflight.yml"}


def main():
    found = {p.name for p in WORKFLOWS.iterdir()} if WORKFLOWS.is_dir() else set()
    if found != APPROVED:
        raise SystemExit(f"D-118: unexpected workflows: {sorted(found ^ APPROVED)}")
    workflow = WORKFLOWS / next(iter(APPROVED))
    if workflow.is_symlink() or not workflow.is_file():
        raise SystemExit("D-118: workflow must be a regular file")
    text = workflow.read_text(encoding="utf-8")
    required = (
        "KEYSTORE_BASE64", "KEYSTORE_PASSWORD", "KEY_ALIAS", "KEY_PASSWORD",
        "tools/zapret2/vendor.py", "go test ./bridge",
        ":connection:test", ":app:testDebugUnitTest", ":app:lint",
        "tools/zapret2/check_apk_assets.py", "sign_apks.py",
        "--pinned-fingerprint", "--prerelease", "github.ref_name",
    )
    missing = [item for item in required if item not in text]
    if missing:
        raise SystemExit(f"D-118: missing signed alpha safeguards: {missing}")
    print("D-118: approved signed Android alpha workflow and safeguards verified")


if __name__ == "__main__":
    main()
