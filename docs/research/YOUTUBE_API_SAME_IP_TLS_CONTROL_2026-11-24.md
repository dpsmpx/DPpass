# DPpass 0.7.73 — same-pinned-IP, certificate-verified Google SNI control

## Evidence that motivated this revision

Android MOBILE 0.7.72 on 2026-11-24:
- `youtubei.googleapis.com` DoH: eight public A records, hash
  `6f706c12`. On those eight addresses, five profiles
  (HTTP1/plain, HTTP1/tlsrec-split, HTTP2/plain, HTTP2/tlsrec-split,
  HTTP2/fake-5) each failed after ClientHello, **0/40** cert-verified TLS
  handshakes and zero HTTP replies.
- Independent `i.ytimg.com` fixed JPEG: **42/42** verified content
  (including 6/6 on plain). The CDN is reachable; this is separate
  infrastructure and doesn't establish anything about the API addresses.
- The YouTube app shows some historical shorts preview items, but
  the feed fails to refresh. No successful browsing/API payload has been
  established through local serverless routing.

## Opt-in SNI/control experiment

New diagnostic button in Zapret2 screen compares, using the **identical
eight public API DoH addresses** and the same protected Xray test outbound:
- Original destination `youtubei.googleapis.com`, TLS SNI/HTTP Host of the
  API; unmodified TCP plain, HTTP1.1 GET to fixed transport-only path.
- **Control identity `www.google.com` on the exact same IP**, with
  certificate verification for `www.google.com`, TLS SNI and HTTP Host
  `www.google.com`, unmodified TCP plain, HTTP1.1 GET /. This is
  intentionally *only a diagnostic*; some API IPs legitimately may not
  serve Google.com and a failed control is inconclusive.
- Separate independent positive Google control using authenticated Google
  DoH answers to `www.google.com`, independent of the API IP set.

One initial API/control pair per IP (max 16 targeted sockets),
optionally 2 more API/control pairs at up to two IP indices where the
control returned certified HTTP (max 8 confirm sockets), plus up to two
own-IP Google controls and two DoH preparations. Each main TLS probe has
a 5-second bounded deadline. One Google DoH answer, 5-minute generation/
network safety guards; no raw addresses/certificates/HTTP bodies exported.

**Interpretation guard**: only a matched per-IP **3/3 www.google.com
certificate-verified HTTP replies** vs **0/3 YouTube API HTTP replies**
supports a *hostname-/SNI-specific behavior hypothesis*. This does
not distinguish DPI from a server-side virtual-host/policy difference,
and does not prove a working app or a particular censorship mechanism.

**Isolation**: user-triggered only, no background monitoring, no changes
to global DNS, VPN routing, subscriptions, QUIC, existing TCP streams,
AUTO profile, app keys, or neural training. The `site_sni_google_ip`
request type is restricted to the API host, indices 0..7, attempts 1..3
and plain strategy. A shared `siteSearchMayRecord` guard prevents
sweep/control samples (including early dial errors) from poisoning the
native exact-host AUTO 3/3 optimizer.

## Acceptance

- The Go target grammar excludes any user-supplied host, URL, port, IP
  literal or other target; tests verify no AUTO sample admission.
- Kotlin tests show a redacted report and forbid interpreting fewer than
  3 independent paired successes as confirmed SNI-dependent behavior.
- On real MOBILE/WiFi: send the copied report. A positive same-IP
  Google control justifies investigating ClientHello differences and
  hostname-specific treatments next; no same-IP control success means
  this test remains inconclusive.

This release is a diagnosis, **not** a fix for the feed or video playback.
Keep PR draft until physical validation.
