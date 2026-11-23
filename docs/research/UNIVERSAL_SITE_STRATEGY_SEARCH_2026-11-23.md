# DPpass 0.7.69 — opt-in arbitrary-public-host strategy optimizer

Scope: a **real, on-device, user-initiated search** over implemented and
permitted Zapret2 transport methods. It is not a promise to unblock all sites,
and it does not replay private browser requests, cookies, application POSTs or
full video streams. It complements passive per-host/network AUTO in PR #47.

## On-device evidence that prompted the change

At 2026-11-23 13:03:56 +03 (MOBILE), authenticated fixed Google DoH returned
eight indexed IPv4 addresses for `youtubei.googleapis.com` with fingerprint
`6f706c12`. Google protected QUIC v1 controls both passed certificate-verified
TLS 1.3/ALPN h3. All eight YouTube v1 first attempts timed out with no observed
reply; there were no stable 3/3 candidates, no HTTP/3 GET and no anonymous API
POST. Google QUIC v2 twice received Version Negotiation-shaped headers without
completed TLS, so the YouTube v2 matrix was correctly skipped. Older 139-ms
and 162-ms single v1 handshakes did **not** reproduce. No measured result
identifies the cause (DPI, route loss, endpoint selection, MTU, timing).

## How automatic search works

The user enters an explicit **DNS hostname** on the existing Zapret2
diagnostics screen (not a URL or arbitrary port). The native component
verifies it is a valid ASCII/punycode public hostname and denies raw IPs,
local/special DNS suffixes, URL punctuation, userinfo, ports and paths.
Network changes cancel the in-flight search and invalidate native evidence.

1. A `site_prepare:hostname` request fetches **A-only IPv4** from the
   certificate-verified **Google DoH endpoint** via an already registered
   private Xray TCP outbound to the pinned bootstrap. No OS/system DNS or
   UDP/53, redirects, browser requests or public content are involved.
   All private/special-use/reserved results are filtered **before** dial.
   A sanitized answer count/fingerprint returns to Kotlin; raw IPs stay in
   native memory and expire after **five minutes**.
2. The existing Xray private test outbounds (same original VPN socket
   protection and TLS verification) dial the **same up to two pinned IPv4s**
   to compare methods. For HTTPS/TCP there are 7 candidates × 2 IPs ×
   **3 independent connections each**: untouched baseline, one-byte
   split, SNI split, **TLS-record plus TCP split**, TTL3 fake plus TCP
   split, TTL5 fake plus TCP split, and disorder/low TTL.
3. Each request is an anonymous, fixed `GET /` to the original hostname,
   with standard SNI/Host, certificate trust and a bounded **256-byte**
   response. Never follow redirects; never expose a response body.
   A genuine HTTP **2xx plus at least 128 bytes** is a candidate success.
   HTTP 4xx, 3xx, 204 and short/failed responses are not working-page
   evidence, even when they prove transport. This does not establish
   application account access or video media flow.
4. Candidate ranking is **success-first**: it requires **3/3 independently
   numbered successful HTTPS responses on every tested IP**. Intermittent
   1/3 or 2/3 does not win. Among equally stable methods, lower average
   latency wins. If the untouched baseline is already 3/3, **restore
   `pass`**, not a previously stale DPI profile. A new DPI profile may
   be promoted only when the native layer independently confirms the
   baseline is **at most 1/3** on *each* tested IP, while the proposed
   profile is 3/3 on each. The Kotlin planner and the native commit
   independently enforce these criteria.
5. The site-scoped winner is applied to **AUTO for new TCP/TLS connections
   to that exact hostname only**, and only if the current network
   generation matches the original scan. Current streams, manual
   server/route selections, global DNS, other domains/CDNs, other
   protocols and the persisted neural model are not changed.
6. A separate user-initiated **QUIC v1** scan tries original UDP and
   available TTL3/TTL5 fake-Initial methods against the same pinned A
   results, three independent certificate-verified TLS 1.3/ALPN h3
   handshakes each. This finds a **transport-only** candidate; it does
   **not** prove HTTP/3, API results or video. It deliberately does not
   promote a QUIC strategy in live AUTO because a UDP socket may only
   expose a **shared remote IP**, not an authenticated service hostname;
   automatic IP-based promotion could affect unrelated co-hosted sites.
7. There is no background scan, response-body logging, unbounded fuzzing,
   retransmission of user requests, change in TCP socket strategy midstream,
   or use of private subscription credentials. The user can cancel;
   incomplete or expired runs never commit.

Worst-case site HTTPS scan: 7 methods × 2 IP × 3 × 6 seconds, so about
4–5 minutes plus one bounded DoH request; a run nearing TTL aborts rather
than applying an unverified result. The separate QUIC diagnostic uses up
to 3 methods × 2 IP × 3 × 6 seconds. Mobile-data charges and service
rate limits are possible; only explicitly started tests run.

## Research sources and engineering constraints

- Zapret2 `blockcheck2`: generate parameter/method candidates by family,
  vary target endpoint and use repeat measurements rather than one ping:
  https://github.com/bol-van/zapret2
- sing-box `urltest`: compare measured delay with tolerance/hysteresis:
  https://github.com/SagerNet/sing-box/blob/testing/docs/configuration/outbound/urltest.md
- Mihomo `url-test` / `fallback` and `expected-status`:
  https://wiki.metacubex.one/en/config/proxy-groups/
- Happy Eyeballs RFC 8305: bound multiple network/address candidates:
  https://www.rfc-editor.org/rfc/rfc8305
- QUIC loss recovery RFC 9002 and QUIC v2 RFC 9369: a handshake timeout
  is neither proof of blocking nor proof of successful HTTP3:
  https://www.rfc-editor.org/rfc/rfc9002
  https://www.rfc-editor.org/rfc/rfc9369
- Android VpnService: protected native sockets, avoid VPN recursion:
  https://developer.android.com/reference/android/net/VpnService

The project currently supports the finite private test-outbound catalog
listed above, not arbitrary upstream `nfqws2` Lua compositions that
need root/packet capture. Testing extra Lua pipelines without actually
implementing their sockets, synchronization and secure behavior would
produce misleading claims of 'optimizing' unsupported strategies.

## Acceptance checklist

- Go tests for hostname grammar, unsafe/private DNS IP exclusions,
  unique independent samples, one-IP and two-IP confidence, retries,
  stale generation, five-minute expiry, safe return to `pass`.
- Kotlin tests for IDN normalization, exact site-trial target IDs,
  baseline dominance, transient 1/3 and 2/3 failures, candidate ranking,
  QUIC non-promotion, strict wire output and privacy.
- Signed Android ARM64 CI plus real-device **MOBILE and WIFI**:
  run one control site, one known problematic public HTTPS site, then
  the optional QUIC diagnostic. Verify each selected method's actual
  3/3 or non-selection, the prepared DoH fingerprint and that no
  unrelated site, route, DNS or VPN server pin changed.
- Until those physical trials, keep this feature in a draft stacked PR,
  not merged to `main`. The CI suite only proves code correctness and
  buildability, not the ability to restore the YouTube application feed.
