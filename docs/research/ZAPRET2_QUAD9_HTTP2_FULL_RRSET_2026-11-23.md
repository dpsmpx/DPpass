# 23 Nov 2026 — Quad9 HTTP-version differential and full YouTube API IPv4 RRset

> Historical branch record, restored from commit `74af64d64409` during the 2026-11-27 integration. The implementation descriptions below refer to that historical branch, not current production support. The current DPTS/1 contract and physical release gates take precedence. Repeated field observations are not independent measurements.

## Measured on 0.7.60-dev, Android 15 MOBILE

- `youtube_api_ipv4` configured-DNS control: 0/4, all `timeout_tls` (12 s).
- Cloudflare pinned DoH `1.1.1.1`: 4/4 valid eight-address A answers,
  fingerprint `6f706c12`, every one chosen first IPv4 `timeout_tls`.
- Google pinned DoH `8.8.8.8`: same eight-address set fingerprint
  `6f706c12`, and identical first-IP TLS failure.
- Quad9 pinned DoH `9.9.9.9`: 4/4 reached an actual HTTP response
  (`doh_http_status`) in 300–332 ms, **but 0.7.60 discarded the HTTP code**.
  DNS resolution did not complete; calling this DNS blocking is unjustified.

## Implementation flaws fixed in 0.7.61-dev

1. The DoH implementation forcibly advertised `http/1.1` and manually
   wrote HTTP/1.1 requests. Some Quad9 DoH endpoints reject HTTP/1.1
   with HTTP 505 and accept HTTP/2. This is a plausible explanation,
   not a proven interpretation of the unseen original HTTP status.
   The new client supports ALPN `h2` and `http/1.1`, using the Go
   transport with `ForceAttemptHTTP2=true` and a protected, fixed-IP
   custom TLS dialer; provider TLS hostname verification is retained.
2. `doh_http_status` previously lost the resolver HTTP response code.
   New v3 result wire stores resolver HTTP code and negotiated major HTTP
   protocol, distinct from the target YouTube API status.
3. The code selected only the lexicographically first A address from a
   set of eight. The upgraded test checks **every valid public IPv4 A**
   returned (max 16) with bounded 2.1 s per-IP budget, capped by the
   overall attempt deadline (22 s). It reports counts of attempted IPs,
   certificate-verified TLS handshakes and valid HTTP transport replies.
4. Unit tests cover all-address enumeration, late successful address,
   no false TLS/HTTP success, v3 strict decoding, HTTP 505, backward-
   compatible v1/v2 decoding, and unchanged native AUTO training.
5. The normal 96-request HTTPS test is unchanged. The separate 16-run
   DoH differential remains an explicit user action and keeps the
   regular VPN DNS, protected routing, subscriptions, neural training,
   and server strategies untouched.

## Cautions

- A successful response over HTTP/1.1 or HTTP/2 DoH confirms only the
  provider resolver response, not useful YouTube feeds/video.
- Each received A address is tested from that resolver's *one* response,
  not every address ever issued by the CDN.
- The short SHA-256 fingerprint of a public set is not a secret or a
  cryptographic guarantee of non-linkability; it merely avoids printing
  literal resolved addresses in the diagnostic report.
- Both Cloudflare and Google returned identical eight-address sets
  in this field session. The one-address failure did not establish that
  all eight addresses were unusable; the next field test is necessary.
- The cause could still involve destination IP, SNI/TLS DPI, route quality,
  HTTP semantics, etc. Do not promote a global VPN/DNS change from
  2-sample controls.

References:
- Quad9 DoH endpoint (official): https://docs.quad9.net/services/
- Report of HTTP/1.1 505 versus HTTP/2 200 at Quad9, October 2026:
  https://github.com/Start9Labs/start-technologies/issues/4383
- DNS-over-HTTPS protocol: https://www.rfc-editor.org/rfc/rfc8484
- OONI on distinct Russian DNS and TLS interference:
  https://labs.ooni.io/post/2024-russia-report/
