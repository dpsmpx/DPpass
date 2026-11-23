# DPpass 0.7.70: YouTube cross-service H1/H2 evidence, safe standby and QUIC metrics

## Field evidence

On MOBILE, `www.youtube.com` 0.7.69 active strategy search
reported two independent public IPv4s, three trials each:
- unchanged HTTPS, split-1, split, fake-3, disorder: 0/6 successes each, all failed at TLS ClientHello with no reply by ~6 seconds
- `tlsrec-split`: **6/6 certificate-verified HTTP/1.1 200**, 256 bounded bytes, mean 1098 ms; selected for exact `www.youtube.com` (`AUTO: auto_applied`)
- `fake-5`: **6/6**, mean 1235 ms; independently validated runner-up
- QUIC v1: unchanged 0/6, fake-3 0/6, fake-5 1/6 (one 681-ms TLS1.3/h3), *no stable QUIC strategy*. Several QUIC attempts received an unverified public-header Initial but could not complete TLS. No HTTP/3 GET/browse POST or video playback was established by that test.

The new tests and implementation must **not** treat homepage HTTP 200 as YouTube feed or video playback.

## New opt-in YouTube service-path verification

The diagnostics screen has a separate button. It prepares the fixed public,
independently pinned, certificate-verified Google DoH A records of
`www.youtube.com`, `youtubei.googleapis.com` and `i.ytimg.com`
using the original protected Xray private test outbounds, never system DNS
or UDP/53. It then compares original `plain`, `tlsrec-split`, and
`fake-5` on the **same first public A record per service**, two
independent trials each, for **HTTP/1.1 and HTTP/2**.

The fixed, anonymous requests are:
- `www.youtube.com/`: GET /, expect an HTML 2xx with an HTML marker
- `youtubei.googleapis.com/youtubei/v1/browse`: fixed public anonymous
  JSON **POST** context, no credentials; HTTP 2xx/4xx establishes only
  transport, not a functional authorized feed
- `i.ytimg.com/vi/jNQXAC9IVRw/hqdefault.jpg`: a fixed public JPEG
  thumbnail, 2xx, JPEG content-type and magic bytes. This is static
  CDN evidence **not a `googlevideo.com` video stream**.

No redirects or private URLs. Only fixed response codes, ALPN, TLS
phases, bounded byte counts, duration and one-way hashed A-set
fingerprints are returned in the report. Never auto-apply service-wide
changes on the basis of this diagnostic. Address-cache TTL is five
minutes and keyed to the current Xray instance/network generation.
All existing live connections, user route selection and subscription
secrets remain untouched.

## Repeated-failure automatic standby

The native site-search transaction independently validates all three
`GET /` HTTPS attempts on each tested public IP. Only when there is
a 3/3 validated selected strategy and a second independent 3/3 winner
does it record an **exact-host standby** (e.g. tlsrec-split primary,
fake-5 backup). The standby expires after 20 minutes or immediately
on VPN/network generation change. A single first-reply TLS timeout
cannot activate the backup. After two actual first-reply read timeouts,
the specific primary is suspended for 90 seconds; new connections
to that exact hostname use the vetted standby, while already-open
connections and unrelated domains are never moved. At expiry the
original primary is retried. If a standby is stale, missing,
cooled or not 3/3 validated, the historical cautious candidate
rotation is retained instead of assuming a backup.

The automatic fallback is for **new TCP/TLS connections only**, not
the user's manually configured route or VPN server. QUIC IP-level
observations are not attributed to all sites on a shared address.

## QUIC diagnostic precision

The protected original QUIC UDP/443 socket now counts:
- genuine public-header QUIC Initial datagrams sent, including retransmits
- received peer datagrams, not assumed to be authenticated
- elapsed time to first received datagram after the first sent Initial
- size of the largest sent Initial

A bounded v4 wire format adds four **non-payload, non-identifying**
numbers with strict Kotlin validation, preserving v1/v2/v3 parsing.
The existing first received public QUIC header class (Initial/Retry/VN/
Handshake/short/other), certificate-verified TLS and ALPN remain
independent. These metrics help distinguish persistent lack of
responses from incomplete negotiations, but **cannot prove packet
loss, MTU, filtering or working HTTP/3** by themselves.

## Acceptance

CI: Go native safety/fallback and packet-counter tests; Kotlin
contract/report tests; Android debug and optimized signed ARM64,
package/signing certificate and artifact checks. Real Android MOBILE
and Wi-Fi tests are still necessary for site-path results, fallback
on actual new flows, feed scrolling, CDN behaviour and video
playback. Keep draft PR unmerged until real network evidence.
