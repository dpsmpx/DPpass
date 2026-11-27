#!/usr/bin/env python3
"""CLI protocol tests with a child owned by this test only."""
from pathlib import Path
import os
import subprocess
import sys

helper = sys.argv[1]
boot = Path("/proc/sys/kernel/random/boot_id").read_text().strip()


def expect(args, code, output):
    result = subprocess.run([helper, *args], capture_output=True, text=True, timeout=7)
    assert (result.returncode, result.stdout, result.stderr) == (code, output + "\n", ""), result


expect(["--version"], 0, "dppass-root-pidfd/1")
expect(["probe"], 0, "supported")
expect(["absent", "1", boot], 64, "invalid_arguments")
expect(["absent", "2", "unknown"], 64, "invalid_arguments")
expect(["absent", str(os.getpid()), boot], 2, "unproven")
expect([], 64, "invalid_arguments")
for path in ("relative", "/", "/a//b", "/a/../b", "/a/./b", "/a/b/", "/a b", "/a\nb", "/" + "x" * 108):
    expect(["tun-send", path, "10000", "123"], 64, "invalid_arguments")
for uid in ("0", "9999", "010000", "2147483648", "-1"):
    expect(["tun-send", "/tmp/dppass-tun.sock", uid, "123"], 64, "invalid_arguments")
for pid in ("0", "1", "0123", "2147483648", "-1"):
    expect(["tun-send", "/tmp/dppass-tun.sock", "10000", pid], 64, "invalid_arguments")
expect(["tun-send", "/tmp/dppass-tun-nonexistent.sock", "10000", "123"], 2, "tun_unconfirmed")
expect(["tun-send", "/tmp/dppass-tun.sock", "10000", "123", "extra"], 64, "invalid_arguments")
expect(["--version", "extra"], 64, "invalid_arguments")
child = subprocess.Popen(["/bin/sleep", "30"])
try:
    pid = str(child.pid)
    stat = Path(f"/proc/{pid}/stat").read_text()
    ticks = stat.rsplit(") ", 1)[1].split()[19]
    exe = os.readlink(f"/proc/{pid}/exe")
    args = ["stop-executable", pid, ticks, boot, exe, "2000"]
    expect(["absent", pid, boot], 2, "unproven")
    expect(["gone", pid, ticks, boot], 2, "unproven")
    expect(["gone", pid, str(int(ticks) + 1), boot], 0, "exited")
    expect(["gone", pid, ticks, "00000000-0000-0000-0000-000000000000"], 2, "unproven")
    expect(["gone", pid, "-1", boot], 64, "invalid_arguments")
    assert child.poll() is None
    for index, bad in [
        (1, "1"), (1, "0" + pid), (1, "+2"), (1, "2147483648"),
        (2, "-1"), (2, "18446744073709551616"), (2, "00"),
        (3, "unknown"), (4, "relative"), (4, "/bad\npath"),
        (5, "5001"), (5, "-1"), (5, "000"),
    ]:
        altered = args.copy()
        altered[index] = bad
        expect(altered, 64, "invalid_arguments")
        assert child.poll() is None
    expect(args + ["extra"], 64, "invalid_arguments")
    expect(["stop-script", pid, ticks, boot, exe, "relative", "100"], 64, "invalid_arguments")
    for index, wrong in [(2, str(int(ticks) + 1)), (4, "/not-the-child")]:
        altered = args.copy()
        altered[index] = wrong
        expect(altered, 2, "unproven")
        assert child.poll() is None
    expect(args, 0, "exited")
    # Before wait(), the task is dead and may still be a zombie.
    expect(["absent", pid, boot], 0, "exited")
    assert child.wait(timeout=3) == -15
    # The test's reaped PID is normally absent. If reused immediately,
    # the helper must conservatively refuse to declare it absent.
    result = subprocess.run([helper, "absent", pid, boot], capture_output=True, text=True, timeout=7)
    assert (result.returncode, result.stdout) in [(0, "exited\n"), (2, "unproven\n")]
finally:
    if child.poll() is None:
        child.kill()
        child.wait()
print("ROOT pidfd CLI protocol tests passed")
