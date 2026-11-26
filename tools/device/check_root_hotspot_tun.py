#!/usr/bin/env python3
"""D-120: run the isolated TUN instrumentation test on a connected Zenfone.

Pass the locally built ARM64 helper and the matching instrumentation APK.
The debug DPpass app must already be installed. Instrumentation restarts it.
"""
import argparse
import re
import subprocess
import time
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("helper", type=Path)
    parser.add_argument("test_apk", type=Path)
    parser.add_argument("--adb", default="adb")
    parser.add_argument("--serial", help="ADB serial of the target Zenfone")
    args = parser.parse_args()
    adb_prefix = [args.adb] + (["-s", args.serial] if args.serial else [])

    def adb(*command, check=True):
        return subprocess.run([*adb_prefix, *command], capture_output=True,
                              encoding="utf-8", timeout=30, check=check)

    socket = "/data/user/0/com.dpsmpx.dppass/cache/dppass-tun-probe.sock"
    if adb("shell", "getprop ro.product.model").stdout.strip() != "Zenfone Max Pro M1":
        raise SystemExit("Expected Zenfone Max Pro M1")
    if adb("shell", "getenforce").stdout.strip() != "Enforcing":
        raise SystemExit("Expected SELinux Enforcing")
    adb("install", "-r", "-t", str(args.test_apk))
    directory = adb("shell", "mktemp -d /data/local/tmp/dppass-tun.XXXXXXXX").stdout.strip()
    if not re.fullmatch(r"/data/local/tmp/dppass-tun\.[A-Za-z0-9]{8}", directory):
        raise SystemExit("Unexpected device staging path")
    try:
        adb("push", str(args.helper), f"{directory}/probe")
        adb("shell", f"chmod 700 {directory}/probe")
        case = "RootHotspotManual.receiveTun"
        runner = "com.dpsmpx.dppass.test/com.dpsmpx.dppass.app.device.DeviceTestRunner"
        with subprocess.Popen([*adb_prefix, "shell", "am", "instrument", "-w", "-e", "tests", case, runner],
                              stdout=subprocess.PIPE, stderr=subprocess.STDOUT, encoding="utf-8") as process:
            try:
                deadline = time.monotonic() + 10
                while process.poll() is None and time.monotonic() < deadline:
                    if adb("shell", f"su -c 'test -S {socket}'", check=False).returncode == 0:
                        adb("shell", f"su -c 'unshare -n {directory}/probe send {socket}'")
                        break
                    time.sleep(0.2)
                output, _ = process.communicate(timeout=20)
                print(output)
                if process.returncode != 0 or f"✓ {case}" not in output:
                    raise SystemExit("TUN instrumentation failed")
            finally:
                if process.poll() is None:
                    process.kill()
                    process.communicate()
    finally:
        adb("shell", f"rm -f {directory}/probe && rmdir {directory}")


if __name__ == "__main__":
    main()
