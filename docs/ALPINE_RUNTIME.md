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

## Zapret2 strategy architecture (single shared implementation)

**There is one portable strategy implementation** in
`tools/xray/zapret2/`: strategy catalog and TTL limits, TLS ClientHello/SNI,
HTTP Host, QUIC v1/v2 Initial, decoy building and TCP/UDP first-payload plans.
The Android Xray package `tools/xray/bridge/desync.go` no longer contains
independent packet parsing or decoy algorithms; it is a **transport adapter**
that performs the protected-socket writes, TCP TTL changes, vmsplice and
UDP sends already required on Android.

The same Go package builds the optional static ARM64 executable
`/usr/local/bin/dppass-zapret2` *inside Alpine*.

When the user selects **Zapret2 → VpnService** in an opt-in ARM64 build:

1. DPpass verifies and installs Alpine 3.24.3 and ensures the packaged
   `dppass-zapret2` executable matches the APK's SHA-256 (existing Alpine
   installations are upgraded in place without deleting packages).
2. `DPpassVpnService` starts the Alpine daemon through PRoot and probes
   an app-private Unix-domain socket under the guest's `/root`.
3. The Go JNI bridge selects that Unix socket. For initial TCP/UDP data,
   the Android adapter requests a strategy **plan** from Alpine.
4. Alpine selects the split position, TTL, and any TLS/QUIC decoy bytes;
   Android transmits through its already-protected outbound socket, with no
   external VPN or server and no root permissions.
5. When the tunnel stops, the Alpine daemon is stopped **after** the engine.
   If the selected Alpine daemon dies, planning returns an error rather
   than silently using unmodified direct traffic. A service watchdog also
   marks the session failed.

The protocol is defined only once in `tools/xray/zapret2/client.go`:
JSON request (tag, network, first bytes) and JSON response (plan/error),
one connection per decision, bounded packet and response size with deadlines.
No listener is exposed on a network TCP/UDP port. User TLS payloads are
not logged or persisted by the strategy daemon.

**Default DPpass APKs without `-Pdppass.alpine=true`** still call this
**same** planner package in-process; the Go strategy algorithm is not
duplicated. They do not start PRoot. Opt-in APKs make Alpine the runtime
decision authority for the local no-root mode.

### Privileged NFQUEUE is necessarily a separate OS adapter

The root-backed path still has to execute the pinned upstream
`nfqws2` using `su` and kernel NFQUEUE hooks, and manage their
iptables/watchdog cleanup **outside PRoot**. Alpine fake UID=0 grants
neither `CAP_NET_ADMIN` nor NFQUEUE. Copying `nfqws2` and upstream Lua
into `/opt/dppass/zapret2` inside Alpine makes the assets inspectable
and available to future adapters, but it does not make the Android binary
privileged or executable under the Alpine musl ABI.

The Android `Zapret2RootProfiles` configuration remains a platform
adapter for the original upstream Lua engine; it is **not the same
algorithm** as the experimental no-root Go transport and cannot simply
be replaced by a PRoot process. The Kotlin app still owns Android VPN,
user settings and root firewall lifecycle.

### Acceptance status

CI tests strategy parsing, TCP/QUIC plans, a real Unix-socket decision,
fail-closed behavior on daemon failure, Kotlin unit tests, and a full
ARM64 APK containing verified PRoot, Lua and Alpine strategy executable.
These checks **do not establish** that PRoot executes the daemon correctly
on a physical Android device or that YouTube's home, comments and actual
`googlevideo.com` playback work over a mobile operator. All prior failed
YouTube trials remain valid; no more of the same diagnostics are needed.
Keep the PR experimental until live device acceptance.

## Next software milestone: strict transport errors and repeated QUIC Initial

On 22 November 2026 the Android protected-socket adapter was tightened:

- A selected but invalid Zapret2 strategy now rejects the outbound dial
  instead of connecting without the strategy.
- TCP fake TTL, disorder or split **transport failures** no longer fall back
  to sending the original ClientHello/HTTP request directly. Subsequent
  writes on that connection also fail, so a transient injection problem
  cannot silently disable the selected profile.
- On UDP, failure to transmit the dummy QUIC flight or restore TTL prevents
  sending the unmodified actual Initial as an unintended fallback.
- QUIC Initial **retransmissions** are now eligible for the same central
  Alpine strategy planner, rather than only the very first UDP Write. A
  preceding non-Initial datagram does not consume the retry budget.
  Up to eight Initial flights are planned per connection; further Initial
  attempts fail closed instead of consuming unbounded radio bandwidth.
  Other UDP datagrams retain normal transport behavior.

These measures are transport correctness and reliability improvements, **not
proof of DPI bypass or YouTube playback**. On-device testing is still required.

### Installable test build from CI

The opt-in Alpine job publishes an **ARM64 debug APK** as the
`DPpass-Alpine-Zapret2-ARM64-debug` artifact on the workflow run.
To avoid replacing the user's stable DPpass app with a debug-signed APK, the
test APK uses a separate application ID, `com.dpsmpx.dppass.alpine`, and
launcher name **DPpass Alpine (test)**. Stable DPpass data remains separate.

Each CI job may use a different Android debug signing key. If Android rejects
an update of the *test* app due to a certificate mismatch, uninstall **only**
`com.dpsmpx.dppass.alpine`, not the stable `com.dpsmpx.dppass` app.
The artifact has a 21-day retention period. It is not a public signed
production release.

Unverified physical acceptance items remain: PRoot starts successfully on
ARM64 Android 15, the Unix-socket planner continues to work after
screen-off and Wi-Fi/LTE handover, and YouTube's home/comments/preview/video
flows actually function in the target mobile network. Do not close these
items based solely on CI.
