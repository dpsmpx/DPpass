# DPTest Script (DPTS/1) — v0.8.0-alpha1 foundation

This is an **actual, built-in interpreter**, not a general-purpose runtime or
a way to execute downloaded native code. It makes diagnostic permutations
user-editable without rebuilding an APK, provided the underlying protected
test adapter already supports the capability.

## Syntax

```text
dpts 1
name Compare the API and Google control
host youtubei.googleapis.com
learn observe
sni ips=2 attempts=3 timeout_ms=5000
tls versions=12,13 methods=plain compare_google=true ips=2 attempts=3 timeout_ms=5000
```

Exactly one public DNS `host`; DNS is prepared once through existing
certificate-verified fixed Google DoH using the original protected socket.
No raw IPv4, URL, path, port, cookie, account token, custom header, arbitrary
binary ClientHello or uploaded program is allowed in scripts.

Each operation is a **finite Cartesian product**. Comma-separated lists
cannot contain empty/duplicate/unknown items.

| Instruction | Existing engine capability | Example |
|---|---|---|
| `https` | TLS-verified GET using H1/H2 and actual public server identity | `https protocols=h1,h2 methods=plain,tlsrec-split ips=2 attempts=3 timeout_ms=5000` |
| `tls` | Force TLS 1.2 / 1.3, original SNI, verified cert | `tls versions=12,13 methods=plain ips=2 attempts=3 timeout_ms=5000` |
| `quic` | QUIC v1 TLS h3 handshake transport only | `quic methods=plain,fake-5 ips=2 attempts=3 timeout_ms=5000` |
| `sni` | Two fixed certificate-verified identities on same YouTube API IP | `sni ips=2 attempts=3 timeout_ms=5000` |
| `learn observe` | Export labelled, sanitized test results for review only | `learn observe` |

For the `tls` instruction, `compare_google=true` is only supported
for `youtubei.googleapis.com`, and only with `plain`. It pairs each
version with the existing exact-IP www.google.com certificate-verified control.

Supported physical TCP methods: `plain`, `split-1`, `split`,
`tlsrec-split`, `fake-3`, `fake-5`, `disorder`.
Supported QUIC methods: `plain`, `fake-3`, `fake-5`.
None is a claim of a successful API browse POST, thumbnail for every URL,
HTTP/3 GET, playable video or full censorship circumvention.

Bundled **editable scripts**: eight presets including API IPv4 H1/H2,
original seven-method scan, same-IP SNI, TLS1.2/1.3, public thumbnail,
homepage, QUIC handshake and Google baseline. The UI keeps the last edited
script as private local preferences (no results or IPs). Complete logs are
automatically copied to the clipboard, matching the existing test UX.

## Independent security gates

- Kotlin compiles the entire text **before** any probe; unknown statements,
  keys, TLS protocols, methods and parameters fail closed.
- Go independently checks fixed canonical target identifiers, public DNS
  names, public IPv4 filter, method/transport compatibility, 1..3 attempts,
  bounded TTL and valid index 0..7. Failures are not recorded as AUTO
  evidence: `siteSearchMayRecord` only accepts original trusted `http/quic`.
- Script budget is at most 64 protected diagnostic connections, 240 seconds
  **worst-case declared socket deadlines**, 1..8 public addresses and 1..3
  repeats per cell; native dial timeout is 1..15 sec.
- DNS cache is generation-bound to the same Xray instance and expires after
  five minutes. Android stops (and never labels partial results complete)
  when underlying network or serverless VPN profile changes.
- No script can call `site_apply`, modify routing/DNS, access files,
  read user traffic, spawn a shell, modify subscription servers or install
  models. System root, network namespaces, raw packets and NFQUEUE are
  not exposed through the Android UI.
- Only fixed public thumbnail/API paths from the built-in native target
  catalog are used; arbitrary GET/POST contents and private account data
  are **not** part of v1.

## Neural learning integration: intentionally staged

The existing live adaptive neural model only learns from its own
runtime downstream-flow evidence and has a separate protected weight
snapshot. **DPTS `learn observe` does not update weights**:
an isolated TLS handshake, HTTP 301/404 or bounded 256-byte JPEG prefix
is insufficient to teach the model that a strategy makes an authenticated
feed or video work. The report makes this explicit.

The next release will introduce a *shared* vetted evidence schema with
unique network/host/transport context, repeated independent 3/3 matched
controls and real downstream content validation, before an opt-in
`learn verified` can commit any sample. Script authors must not be able
to falsify outcome labels or turn one-off probes into neural rewards.
All changes to model weights require model-version checks and rollback.

## Strategy compatibility roadmap (not claimed implemented)

Relevant upstream source references:
- zapret2 `nfqws2` Lua hooks, fake, multisplit/multidisorder, TCP
  sequence overlap, md5sig, raw IPv4/IPv6 TTL and payload selectors;
- zapret classic: fake, fakedsplit, multisplit, disorder, seq overlap;
- ByeDPI: split offsets, disorder, fake and out-of-band options, TCP
  fast open, UDP fake count, fake offsets;
- ByeByeDPI: Android VpnService forwarding, selected proxy methods.

These are **not functionally identical** to the seven currently installed
Xray test outbounds. The following require native implementations, isolated
capability negotiation, integration tests, license review and Android
VpnService feasibility checks: arbitrary TCP sequence overlays, badseq,
md5sig, packet injection/NFQUEUE, HTTP out-of-band, TLS ClientHello
extension order/fingerprint mutation, synthetic QUIC Initial transformations,
TLS padding and customizable fakes. Missing capabilities must fail closed,
never silently be emulated or marked successful.

## Remaining gates

1. CI: Go native grammar, JVM parser, Android debug and optimized ARM64
   release, APK signature and versionCode.
2. On-device: paste a script, load each preset, verify correct DoH IP
   selection and automatic clipboard logs; cancel and network-switch
   while a run is executing; confirm no AUTO or model-weight changes.
3. Follow-up: migrate the legacy single-purpose diagnostic buttons
   *after* corresponding script presets show matching real-world results.
4. Implement the broader native strategy catalog and strictly controlled
   neural training in separate reviewed increments.

**This is an alpha foundation, not completion of the full upstream method
catalog or a guarantee that YouTube feed playback has been restored.**


## 0.8.1-dev: unified scripting user interface

The Settings menu is now **"Script Testing" / "Тестирование скриптами"**.
The screen contains only DPTS script controls: preset selector, Load,
script name/editor, Save, Run, Train neural, Stop, progress/status and the
selectable automatically copied report. No old one-off test buttons are
shown. Up to 30 named drafts are saved privately on-device and can be
loaded/edited again. No remote script fetching, arbitrary code execution
or user-submitted URL access is allowed.

Every former single-purpose diagnostics button was exposed as a **finite,
strictly allowlisted DPTS suite**:

```text
dpts 1
name Full original site search
host www.youtube.com
suite site_https
```

Accepted suites (one per script, cannot mix with a matrix):
`google_youtube`, `dns_compare`, `ip_matrix`, `h3_api`,
`site_https`, `site_quic`, `api_ipv4_sweep`,
`sni_control`, `tls_versions`. The corresponding original
procedures and auto-copied reports are preserved rather than silently
truncated to the smaller DPTS generic matrix. In addition to the
existing eight generic presets, nine migrated routine presets are
provided, totalling **17 built-in editable presets**. Suite commands
are intentionally fixed/bounded existing implementations: unlike the
generic `https` matrix, they cannot yet be arbitrarily recombined
with other steps in a single script.

### Opt-in neural training

The **Train neural model from completed script** action trains the
*existing* locally installed STRATEGY MLP, not a synthetic UI counter.

- The user must have executed a complete generic DPTS/1 script with
  `learn observe`, with the same current network and no partial
  execution, and must explicitly press Train once.
- A stable training pair must be on the exact HTTPS
  `www.youtube.com` fixed public homepage, HTTP/1.1, with
  independently certificate-verified HTTP 200–299 and at least
  128 bounded response bytes, **3/3 attempts on each of two public IP
  indices** for one implemented TCP candidate. Baseline `plain` must
  have no such content-verified response on either IP in its own 3/3.
  Both candidate and baseline must have an exactly matching, complete,
  unique step per attempt; duplicated/missing/misaligned observations
  invalidate learning.
- A genuine 3/3 success only proves the tested bounded HTML content,
  not YouTube API authenticated POST, live feed, CDN media or playback.
  No unsuccessful method is given a negative neural reward, since
  `clienthello_sent` + timeout does not determine cause.
- Kotlin independently checks the evidence. Native Go validates the
  finite strategy method set, network generation context and installed
  modern MLP, then applies a small positive logistic gradient
  (at most 0.02 per qualified method) only to the corresponding
  MOBILE/WIFI TCP contextual output head. It does **not** pin AUTO,
  override protective circuit breakers or modify routes.
- Weights are exported through the existing native dirty snapshot
  path and saved atomically with the model-seed guard; the native
  snapshot is acknowledged only after durable storage.
- A `0/32` transport-failure report for `youtubei.googleapis.com`,
  QUIC-only proofs, 301/404, content-invalid replies and one-off
  TLS successes are **ineligible**. The app informs the user instead
  of silently "training" on zero useful data.

**Device acceptance:** verify script loading/saving, screen transitions,
legacy suite reports, editor persistence, clipboard after full results,
Stop midway, network switch/reconnect, no AUTO changes, learning refusal
on the current API `0/32` report, and controlled training on a real
2-IP 3/3 matched HTML result. Keep PR draft until physical tests.

## 0.8.2 — additional native diagnostic profiles

DPTS accepts `split-2` (actual TCP split after two TLS bytes), `fake-2`, `fake-4`, `fake-8` (existing native decoy mechanism with distinct TTLs). The fake profiles also accept QUIC. These are Zapret2/ByeDPI-style local techniques, not imports of either upstream executable. Private protected test outbounds are generated for these explicit profiles, and the native DPTS validator independently accepts them. Legacy matrices, AUTO candidate dimensions and verified neural training allowlist remain unchanged. The new bounded preset compares the additional TCP profiles against plain; results do not promote AUTO. Full upstream integration is not yet implemented.

## Local HTTP self-test

`host example.com` and `suite local_http_hostcase` (with `learn off` or omitted) select the fixed local self-test. The host is a fixture label, never resolved. A plain and an HTTP Host field-name case request are checked over loopback for exact bytes, HTTP semantics and request-owned counters. No remote connections or TLS; the result is not learning evidence. `http-hostcase` is not a valid HTTPS/TLS/QUIC method in script matrices.

## Per-method matrix results

Generic DPTS reports now include an ordered summary grouped by phase, protocol and method. Each row uses the original planned denominator, and counts only observations matching the exact probe and prepared DNS set. TLS verification, transport reachability, bounded HTTP success and fixed-target content verification remain distinct. The median elapsed time (integer milliseconds, rounded down for an even sample) uses only verified transport replies; no reply is shown as `-`. This is elapsed probe time, not throughput or a recommendation to change AUTO. Cancelled and mismatched observations cannot inflate the verified counts. The plan validator also rebinds host, phase, protocol, index and attempt to the canonical native target before reporting or learning. Existing DPTS grammar, methods, and training thresholds are unchanged.

The same local HTTP suite also checks `http-hostows`: a same-length rewrite of existing optional whitespace immediately after the Host colon to horizontal tabs. The Host name, value, request framing and body remain unchanged. The suite now runs three fixed loopback cases (plain, field name case, leading OWS); neither rewrite is available in generic HTTPS or QUIC matrices, AUTO or learning.

## Local certificate-verified TLS self-test

`host example.com`, `suite local_tls` and `learn off` (or omitted) select a six-case loopback matrix: TLS 1.2 and TLS 1.3, each with plain, multisplit and tlsrec-split. Every case creates an ephemeral ECDSA certificate, trusts it only in the local client, verifies the fixed name and exact TLS version/ALPN, and exchanges fixed application bytes in both directions. The actual TCP adapter and currently selected planner are exercised for the two non-baseline methods. Only request-owned application counters are reported. No external DNS, sockets, global certificate changes, AUTO changes or training. The host is a fixture label. A successful result proves local TLS/application integrity, not actual TCP segmentation or remote reachability.

## Interrupted matrix reports

A matrix that stops after DNS preparation retains only the previously admitted rows, with planned denominators, missing-row counts and an explicit `RUN: interrupted; reason=...` marker. Supported reasons: user_stop, session_changed, budget_expired, execution_error, dns_preparation_failed. Every interrupted report is export-only, declares complete_evidence=false and cannot create a trainable completed run even if all rows arrived. Same-session interruption or explicit Stop automatically copies the partial report; stale-session results do not replace the clipboard. Leaving the screen or automatic cancellation does not export late results. If preparation never returned, the existing incomplete message is shown. Fixed suite presets retain their existing behavior.

The fixed local HTTP and TLS suites also retain partial reports, with explicit interruption reason, executed/planned count and missing count. They use one executor and one verifier, with no training eligibility in either complete or partial reports. Both suites use a bounded 5-second-per-case execution budget plus 5 seconds total overhead, never resolve external hosts, and do not copy stale-session results. The HTTP/TLS case lists and native endpoints are unchanged.
