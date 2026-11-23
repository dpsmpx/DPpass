# DPpass 0.7.63-dev — YouTube API QUIC stability and real HTTP/3

## Field evidence, 23 Nov 2026, MOBILE, DPpass 0.7.62

- Three protected DoH providers (Cloudflare, Google and Quad9) returned the
  same verified 8-address A answer set for `youtubei.googleapis.com`.
- The baseline `www.google.com` control demonstrated that the protected
  Xray TCP and UDP transports work: 4/4 HTTPS, 2/2 QUIC/TLS h3.
- All 48 YouTube API TCP ClientHello trials received no TLS reply.
- One YouTube API QUIC handshake succeeded at sorted **IPv4 index 3** (120 ms,
  verified QUIC TLS 1.3 and ALPN h3); indices 0–2, 4–7 timed out.
- A single QUIC handshake does **not** prove HTTP/3 request processing,
  repeatability, YouTube browse API, recommendations or video playback.

## Fixed opt-in experiment

1. The user explicitly clicks **Retest YouTube QUIC + real HTTP/3 API**.
2. Native Xray sends a fixed RFC 8484 DoH A query for only
   `youtubei.googleapis.com` through pinned `dns.google` TCP/443, verifies
   the certificate and returns **only** a short fingerprint and IPv4 count.
   The underlying sorted addresses are held in native memory. Preparation
   invalidates previous experimental selections; the new set expires after
   **five minutes** or when the Xray instance changes. The current device
   network is checked through VpnService, but IP refresh is always required
   for each user-initiated run.
3. Attempt one protected QUIC TLS 1.3 handshake for each of up to 16 fixed
   indexed public IPv4 A records. Each positive result is retried up to two
   further times, on **independent** Xray UDP/443 sessions, requiring 3/3
   verified TLS+ALPN h3 results. Failure disqualifies the address.
4. For each stable candidate, open the **same pinned, protected UDP Xray
   QUIC transport** and send an actual HTTP/3 `GET /`, with fixed
   `youtubei.googleapis.com` SNI/Host and full TLS certificate validation.
   HTTP 2xx/4xx proves H3 transport response, not API use.
5. Only if GET reaches HTTP response headers, open a separate protected
   QUIC session and issue an anonymous HTTP/3 JSON **POST
   `/youtubei/v1/browse`** with a hardcoded public Web-client context and
   `FEwhat_to_watch` browse ID. **No API key, OAuth token, session ID,
   cookies, personalized data or user-generated requests** are sent.
6. Status and at most 8 KiB of the body are handled inside Go memory.
   Small valid JSON is reported as `h3_api_json_valid`, but this indicates
   only syntax, not a usable feed. Larger valid JSON is reported
   `h3_api_body_limit` (not a failure proof); 4xx returns
   `h3_api_http_rejected`, indicating protocol reachability but rejection
   by the application.
7. The next stable candidate is attempted if an earlier address fails
   HTTP/3 or the API check. The selected candidate is **never** installed
   into the live VPN routing table or normal YouTube application traffic;
   it is not persisted or used as positive AUTO training data. The
   ephemeral diagnostic choice expires on completion/exit.

## Scope and limitations

QUIC handshake, HTTP/3 GET and an actual fixed unauthenticated YouTube API
POST are separate outcomes. A successful POST with syntactically valid
JSON does not establish that the full YouTube homepage, player, thumbnails,
media from `googlevideo.com` or user recommendations work. Only real-device
testing can establish that.

The experiment does not send unprotected packets, set a custom Android DNS,
record raw network addresses, or change global split/QUIC policy. It is
opt-in and will not run when normal VPN is in server mode.

## 0.7.64 follow-up: same-run protected Google QUIC control

The 23 November 2026 10:10 (+03) MOBILE field retest returned 0/8
YouTube QUIC TLS/ALPN successes. One indexed IPv4 delivered a UDP packet but
did not complete TLS; all other indices had no registered reply. No HTTP/3
GET or anonymous browse POST ran, and the previous single success at index 3
did not reproduce. This is **not proof** of either an application defect
or YouTube-specific filtering.

The dedicated H3 action now resolves a separate fixed `www.google.com`
A-record set through the same certificate-verified private Google DoH and
probes one indexed Google QUIC IP **before and after** the YouTube matrix.
All QUIC packets still use the existing protected Xray UDP/443 connection
adapter; no direct UDP socket, unprotected DNS or live VPN strategy changes
are introduced. The report marks missing/failed controls as insufficient
to infer YouTube-specific filtering.

The three independent successfully verified YouTube QUIC/ALPN h3
handshakes remain mandatory before HTTP/3 GET and the anonymous fixed API
POST. Neither the control nor a one-off QUIC handshake is positive AUTO
training evidence. The signed ARM64 development build version is
`0.7.64-dev` (`versionCode 142`); field validation remains open.

## Verification

- Go strict allowlist, 5-minute address expiry and malformed target tests;
  native error/classification tests; localhost full QUIC/TLS/HTTP3 GET and
  browse POST integration tests with a test certificate.
- Kotlin schema v3, report privacy, three-success selection, expiry and
  negative/positive API interpretation tests.
- GitHub Actions Go + JVM regression suites, optimized signed ARM64
  Android app, signed APK identity and experimental alpha certificate checks.
- Field check: run the single H3 button under the same mobile VpnService,
  paste the copied report, compare the stable IPv4 indices and GET / browse
  response codes against the v0.7.62 evidence.
