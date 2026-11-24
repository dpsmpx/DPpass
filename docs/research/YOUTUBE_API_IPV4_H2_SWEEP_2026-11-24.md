# DPpass 0.7.72: bounded YouTube API 8-IPv4 HTTP/1.1 vs HTTP/2 differential

## Real MOBILE field results in 0.7.71 (2026-11-24)

- `i.ytimg.com` pinned public JPEG worked on both tested IPv4 with all
  methods: **42/42 TLS + HTTP 200 + image/jpeg / JPEG magic**; unmodified
  `plain` **6/6**, ~308ms. The site-specific native AUTO correctly restored
  `pass`, which is not evidence of a working YouTube feed.
- `youtubei.googleapis.com` **0/42 TLS handshakes**, two sorted public
  Google DoH IPv4s, 7 TCP profiles and 3 independent attempts each.
  Every probe sent ClientHello and timed out around six seconds.
- The user reports that older cached shorts previews load, but the feed
  does not refresh. This is compatible with the API transport failure,
  but it does not rule out other application/API and routing problems.
- Serverless profile used `quic_force_tcp=true` (no QUIC trials). Periodic
  `tcp_dial_unreachable_ipv6` counters coexist with IPv4 TLS stage
  timeouts, and cannot be assumed the cause of this specific IPv4 error.
- Google DoH returned **8 A records**, only first 2 were checked by the
  fully verified 7-method×3-repeat AUTO optimizer. DO NOT extrapolate
  these two failures to the other six addresses.

## Added opt-in button

`Проверить все IPv4 API / HTTP2 (диагностика)` in the Zapret2 diagnostics
screen. It **does not** replace the strict 3/3 optimizer.

- Same manually requested API host: `youtubei.googleapis.com`. No URL,
  path, port, cookie, credential or raw IP from the UI.
- One certificate-verified Google DoH A-only answer (max 8 vetted public
  IPv4), bounded to the same native instance and network generation and
  five-minute cache. Same pinned IP set and SNI/HTTP Host.
- Per IPv4, five one-time profiles: H1/plain, H1/tlsrec-split, H2/plain,
  H2/tlsrec-split, H2/fake-5. Each creates an independent protected
  socket via Xray's **existing** test outbounds, with a five-second
  deadline. H2 negotiates ALPN `h2` and makes anonymous GET
  `/youtubei/v1/browse` over HTTP/2. An HTTP 4xx proves transport
  only, never a useful browse feed.
- If any HTTP response arrived, the first two candidate pairs get
  up to two independent confirmation attempts. Single samples are
  NOT stable 3/3 evidence.
- Bounded total: 40 initial TCP probes + max 4 confirm probes (up
  to 44). Stops when cache/network changes; never persists IPs,
  request bodies, URLs, cookies, TLS certificates or endpoint tokens.
- All results are reported with **IP indices only**, H1/H2, TLS stage,
  ALPN, HTTP status, elapsed time. The sweep **never calls site_apply**
  or siteSearchRecord and cannot promote any profile to AUTO or
  influence live TCP/QUIC/MLP routing.

## Interpretation and follow-up

1. If H2 returns TLS but H1 does not on the *same indexed address*,
   the protocol/TLS fingerprint is a useful hypothesis, not proof
   that the real Android YouTube client can use the profile.
2. If one of the last six IPv4s is successful, repeat a full matched
   3/3 test on it before considering any native strategy promotion.
   This release does not auto-promote a site sweep.
3. If 0/40, compare the existing protected Cloudflare/Google/Quad9
   fixed-DoH evidence and isolated mobile/Wi-Fi results. Failure
   cannot be labeled with a unique DPI cause based on this scan.
4. Do not merge to main or claim working YouTube until an actual feed,
   thumbnail and video playback succeeds on a physical device.

Potential separate improvements: introduce authenticated API POST-only
transport diagnostics with **no private account/key** (not implemented),
QUIC v1/v2 control with proper H3 GET before any UDP adaptation, and
real application-level replay after a new strategy passes the strict
network health gates.
