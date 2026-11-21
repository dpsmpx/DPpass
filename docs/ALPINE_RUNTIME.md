# Alpine Linux in DPpass (experimental)

Source and implementation reference: private `dpsmpx/DPmetaApp` repository,
subsystem `dpai`, revision `8fb07caffcc6a3a60511b7da929eaddd287a5944`.

Components examined:
- `dpai/tools/linux/build-proot.sh`, `proot-musl-compat.h`: pinned Termux
  fork of PRoot, built static with the detached loader;
- `dpai/android/src/main/cpp/dpai_native.c`: JNI process sessions, PTY,
  signals, fork/exec and file descriptors;
- `dpai/execution/linux/ProotHost.kt`: PRoot arguments, guest-only environment
  and restricted /dev mounts;
- `dpai/orchestrator/linux/RootfsInstaller.kt`: staged tar unpack, symlinks,
  traversal checks and incomplete-installation recovery.

## Build (opt-in only)

```sh
./gradlew :app:assembleDebug -Pdppass.alpine=true -Pdppass.nativeAbis=arm64-v8a
```

This builds PRoot from the Termux source at commit
`52d65a4dc140ca554d241a1438ddd4f6b00c9813`, with pinned Alpine 3.24
sysroot packages and the Android NDK. The build embeds the unmodified Alpine
3.24.3 aarch64 minirootfs archive, SHA-256
`4d3f80afaebd447c5591a63a73bde380a149fe8b2d85488cafabb2ff97551f50`.
Build scripts verify downloaded bytes, and first install verifies the checksum
again. The JNI PTY library comes from DPmetaApp and is built by CMake.
Without the opt-in flag normal DPpass APKs do not bundle the rootfs or PRoot.

From **Settings → Alpine Linux terminal** install the rootfs into private
application storage and start `/bin/sh -l`. This is a minimal line-oriented
terminal (`TERM=dumb`), with command input and Esc, Tab and Ctrl-C buttons.
The full dpai ANSI emulator, terminal tabs, IDE and AI agent are not ported:
the initial goal is a small reliable local shell. Full-screen TUI programs
are unsupported in this first version.

The installer rejects archive path traversal, writes only into a fresh staging
root, does not write through symlink ancestors, and does not mark installation
ready until the archive is fully unpacked. PRoot uses a fake UID=0, does not
mount /sys, exposes only minimal /dev paths and does not inherit Android's
environment. The shell is terminated when its Activity is destroyed. DNS
resolvers are refreshed from Android's active link properties at shell start.

## Important network boundary

PRoot **does not grant Android root**, CAP_NET_ADMIN, NFQUEUE, iptables/nftables
or raw sockets. An unmodified `nfqws2` process inside this Alpine cannot
intercept Android device traffic. Guest processes share the app's normal
network privileges. They are **not wired into VpnService's TUN**; the existing
VPN core and YouTube desync behavior have not been changed by this port.
A separate user-space packet adapter is needed before Alpine-side code can
participate in VPN routing.

Device installation, interactive shell correctness, real-world packet tests
and YouTube playback are NOT yet verified. The dedicated Actions workflow
checks build and package integrity, not the live phone environment.
