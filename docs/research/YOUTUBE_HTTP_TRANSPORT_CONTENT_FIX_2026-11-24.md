# DPpass 0.7.71 — separate HTTP transport reachability and content verification

## Real-device evidence (MOBILE, 0.7.70)

- `i.ytimg.com`: on two pinned public IPv4 addresses and seven methods, all
  42 independent TLS connections completed and returned **HTTP 404** for
  the tested **root path /**. This proves reachable HTTPS transport but not
  that the intended thumbnail loaded. Marking every method 0/6 "failed"
  obscured the distinction.
- `google.com`: all 21 TLS connections returned **HTTP 301** for root,
  again transport was reachable without packet modification. A redirect is
  not missing TLS/server response.
- `youtubei.googleapis.com`: all 42 TLS probes timed out after sending
  ClientHello, including plain, tlsrec-split and fake-5. No stable method
  on the two tested addresses; this code change does not unlock the API.
- Over the long session, local serverless TCP occasionally transferred data,
  but also encountered numerous IPv6 unreachable/dial timeouts. After a
  deliberate switch to a subscription VLESS server there were independent
  ENDPOINT_UNREACHABLE/PAYLOAD_STALLED failures. Do not combine their
  counters or interpret them as YouTube-specific evidence.

## Corrective changes

1. The bounded opt-in HTTPS scan for `i.ytimg.com` now requests the *fixed,
   public* JPEG from the existing catalog:
   `/vi/jNQXAC9IVRw/hqdefault.jpg`, with certificate-verified SNI,
   `image/jpeg`, JPEG SOI magic and at least 128 bounded bytes. This
   is **not** verification of all thumbnails or video streams.
2. `youtubei.googleapis.com` now checks the existing anonymous
   `/youtubei/v1/browse` transport endpoint rather than its `/` root.
   4xx indicates TLS/HTTP reachable; no authorization or usable API data
   is claimed. No credentials, cookies, private user API key or POST body.
3. Kotlin reports *separate counts* for certificate-verified HTTP 2xx..499
   response transport and validated 2xx content/JPEG. A 301/404 baseline
   that passes 3/3 on each IP is labeled `plain`, with no AUTO mutation:
   redirects and 404 cannot justify a DPI method. Stable content
   2xx/JPEG continues to obey the original strict 3/3 admission and
   unchanged native independent validation.
4. Regression tests cover 301, 404, duplicates, insufficient samples,
   pinned public JPEG, API transport, and native refusal to promote
   HTTP-only observations.

No changes to VPN routing, global DNS, UDP or QUIC strategy, subscriptions,
background scans, learned MLP weights or existing flows.

## Remaining field gates

Run the three domain-specific opt-in searches again on MOBILE and WIFI.
For the thumbnail inspect `plain` outcome = `ok`, HTTP 200 and JPEG
body; for Google 301 the report must show transport 3/3 and content 0/3.
For YouTube API, request must still not be labeled a usable authenticated
feed unless a distinct end-to-end probe is implemented. Examine actual
YouTube feed, thumbnails and video using the app, not a browser opened at
the API/CDN root. Keep PR draft until these real-device tests pass.
