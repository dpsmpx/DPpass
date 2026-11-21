# Zapret2 on Android: experimental feature branch

**Not a production release.** The user requested a *full* serverless Zapret2 mode
in addition to subscription mode, for both root and VpnService. They are
technically different backends. Do not relabel the existing Xray serverless
splitter as Zapret2.

## Current implementation
- Distinct persisted `Zapret2Backend` with `OFF` default, independent of
  a Remnawave/Xray subscription or relay.
- The root path stages pinned upstream v1.0.7 `nfqws2` Android binaries and Lua,
  copies them into a root-owned directory, launches the NFQUEUE listener,
  inserts scoped OUTPUT rules for TCP 80/443 and UDP 443, and removes only
  its own matching rules on stop. `--queue-bypass` avoids a dead connection
  if the listener dies. Foreground service monitors process survival.
- The UI labels root experimental and the VpnService option unavailable.
  Selecting the latter fails explicitly: **no fake connected state**.
- A signed-APK workflow uses the four existing GitHub Secrets and checks the
  actual APK with `apksigner`. Unknown key fingerprints are allowed **only**
  in a private preflight release; the production path must verify a pinned key.

## Pinned Zapret2 dependency
`bol-van/zapret2` v1.0.7, MIT license, upstream release tarball SHA-256:

`547a5dce3f4820721a425680ea3f7f3971b7e9c772b8c795dd2d623148da0928`

`python3 tools/zapret2/vendor.py` verifies this SHA-256 before extracting
only three Android ELF executables, Lua source, and the upstream license.
Builds without vendoring cannot claim to contain Zapret2.

## Remaining acceptance gates

1. **Root on actual devices:** verify `su`, Android SELinux execution,
   NFQUEUE target availability, firmware iptables versions, binary startup
   and Lua init, correct packet handling (HTTP/TLS/QUIC), IPv4/IPv6,
   stop/rollback under errors, reboot and concurrent VPN behavior.
2. **VpnService mode not implemented:** implement a real TUN-to-socket
   bidirectional TCP/UDP/QUIC relay with `VpnService.protect`, socket
   ownership, DNS and IPv6 handling, and a genuine Zapret2 userspace
   desynchronization engine. Xray ClientHello fragmentation does not
   satisfy this requirement.
3. **Product parity:** settings for DPI strategies/lists, exclusions,
   app routing, metrics, re-connection and failure recovery. Do not
   silently route traffic through any remote server.
4. **Release:** pass instrumented device tests and DP Verify, then pin
   the signing certificate fingerprint in `docs/PROVENANCE.md`.
   Only after that may an actual public GitHub Release be published.

Current branch should remain a **draft PR** and any APKs a **private draft
release** until these requirements have been met.
