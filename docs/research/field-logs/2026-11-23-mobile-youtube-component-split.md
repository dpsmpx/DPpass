# DPpass 0.7.69 MOBILE — verified HTTPS homepage, unstable QUIC

User-supplied field report (2026-11-23, MOBILE). Exact report timestamp was not included; do not infer a new timestamp.

## Verified per-host, per-protocol evidence

Target `www.youtube.com`, Google protected DoH A-only `dns_ready`, eight IPv4 addresses, sorted set fingerprint `8020f565`.

HTTPS / TLS / HTTP/1.1 (3 independent samples on **each of indices 0 and 1**):
- `plain`: **0/6**; every trial timed out after ClientHello without observing TLS peer reply (~6 seconds)
- `split-1`, `split`, `fake-3`, `disorder`: **0/6** each, same first-reply TLS timeout
- `tlsrec-split`: **6/6** certificate-verified TLS and HTTP 200; 256 bounded response bytes; average **1098 ms**
- `fake-5`: **6/6** certificate-verified TLS and HTTP 200; 256 bounded response bytes; average **1235 ms**
- Native AUTO apply yielded **`auto_applied`** for the exact `www.youtube.com` TLS hostname; no claim of other YouTube service hosts' health.

QUIC v1 (same two sorted IPv4 indices, three independent samples per method):
- `plain` **0/6**; `fake-3` **0/6**; `fake-5` **1/6** (independent verified TLS 1.3 / ALPN h3, elapsed **681 ms**)
- Some attempts received public QUIC Initial-shaped replies without completing the authenticated handshake, other attempts received no UDP response.
- **No QUIC strategy** passed 3/3, and `AUTO: not_applied`. Neither actual H3 GET/POST nor authenticated browse/video succeeded on these observations.

## Implications

- `tlsrec-split` is demonstrably faster than `fake-5` by 137 ms *among successful HTTPS requests in this one run*; the difference is not necessarily stable across networks/times and is not a statistical confidence interval.
- Original TCP could not finish TLS to those **two** tested IPs; this does **not** prove all Google/YouTube CDN addresses are blocked or identify a particular DPI mechanism.
- A successful `www.youtube.com` HTML response is not evidence that the mobile YouTube app can load `youtubei.googleapis.com`, `i.ytimg.com`, or `googlevideo.com`.
- QUIC `fake-5` 1/6 should remain diagnostic only; no 3/3 authorization and no shared-IP AUTO promotion.

## Follow-up in 0.7.70-dev

1. Preserve a real **6/6 site-verified** exact-host AUTO choice across harmless short responses/client closes. Existing weak-flow demotion incorrectly risks unpinning the verified profile after only two legitimate tiny flows. Explicit **two** first-reply TLS read timeouts retain temporary 90s cooldown and release the pin.
2. Add independent read-only, fixed-endpoint **YouTube service components** diagnostics via the existing protected Xray TCP/443, with `plain`, `tlsrec-split`, `fake-5` and three separate probes each for `www.youtube.com/` HTML, `youtubei.googleapis.com/youtubei/v1/browse` anonymous HTTP transport, and `i.ytimg.com/vi/jNQXAC9IVRw/hqdefault.jpg` JPEG.
3. Each component is assessed separately: 2xx valid HTML/JPEG is bounded content proof; anonymous API HTTP 2xx/4xx establishes transport only, not real browse feed or playback. Service probes are **read-only** by separate allowlisted native IDs and do not trigger legacy AUTO training, change global DNS, route, neural weights or current flows.
4. User must opt in on the diagnostics screen. This first iteration uses the active protected Xray outbound's configured DNS for the fixed hostnames, not the extra pinned Google DoH used by site search. Do not claim exact same-IP comparison between components; do not claim video delivery without googlevideo and real video bytes.

Device acceptance remains outstanding. Do not merge stacked PRs until actual MOBILE/WIFI service evidence and app playback tests.
