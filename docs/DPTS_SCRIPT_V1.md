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
