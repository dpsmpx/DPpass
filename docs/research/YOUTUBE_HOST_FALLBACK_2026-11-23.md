# 0.7.70: YouTube multi-host HTTPS and verified AUTO fallback

Field evidence (MOBILE, 2026-11-23): www.youtube.com on two pinned public A
records: plain 0/6, tlsrec-split 6/6 at mean 1098ms, fake-5 6/6 at mean
1235ms, other methods 0/6. Native AUTO returned auto_applied for tlsrec-split.
QUIC v1: plain 0/6, fake-3 0/6, fake-5 1/6 (681ms). This is not stable
HTTP/3 and does not prove feed/API/media functionality.

## Implemented

- Explicit one-tap user-triggered HTTPS strategy scans on
  `www.youtube.com`, `youtubei.googleapis.com` and `i.ytimg.com` in
  the existing diagnostics screen. Each runs the existing bounded 7-method
  × max 2 pinned IPv4 × 3 independently numbered TLS+HTTP/1.1 trials;
  the user runs each separately to respect DoH expiry and avoid unbounded
  requests. Original certificate SNI/Host, no user URLs or cookies.
- On native `site_apply`, retain the fastest other method that passed
  **3/3 on every identical pinned IPv4**, only when the primary passed 3/3
  and baseline <=1/3 on every IP. This is scoped to the exact hostname
  and current network generation; never promoted from QUIC.
- Only after `adaptiveStallThreshold` independent first-reply timeouts
  for the primary, the existing native circuit breaker suspends it and
  atomically switches **new TCP connections** to that validated backup.
  Never changes an existing connection, unrelated hostname, global DNS,
  user VPN server, or neural weights. No backup when no second stable
  candidate exists.
- Reports list the verified backup, or `-`, after AUTO applies.
- Go tests verify primary 3/3, backup 3/3, circuit-breaker activation,
  single-use backup, and exact-host isolation.

## Not claimed

The opt-in homepage/API/thumbnail probes are anonymous GET / transport
checks, not real `youtubei/v1/browse` JSON, image JPEG GET, HTTP/2,
video segment transfer or authorized playback. The existing fixed YouTube
API/thumbnail matrix and protected QUIC H3 diagnostics remain available.
QUIC fake-5's single successful handshake does not justify changing
live UDP AUTO. No new network-wide QUIC packet fragmentation is applied.

## Real device acceptance

Install signed 0.7.70 ARM64 alpha after CI. On MOBILE and WIFI, run the
three one-tap HTTPS probes and the existing YouTube multi-site matrix.
Verify the real app feed, thumbnail, video and seek independently.
Send redacted reports. Do not merge draft PR before this validation.
