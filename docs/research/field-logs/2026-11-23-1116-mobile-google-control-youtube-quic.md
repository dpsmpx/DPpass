# DPpass 0.7.65 MOBILE 11:16 — No YouTube QUIC peer replies

- Date/time: 2026-11-23 11:16:06 +03:00, active protected Android VpnService, network MOBILE.
- Authenticated Google DoH A-only `youtubei.googleapis.com`: HTTP 200, 8 sorted IPv4 addresses; address-set fingerprint `6f706c12`.
- Same-run `www.google.com` QUIC control on the original protected UDP Xray adapter succeeded **2/2**: verified TLS 1.3, ALPN h3 both before and after scanning.
- YouTube API QUIC attempts at sorted indices **0–7**: all **0/1**; timeouts around 5001–5002 ms. Every trial had `quic_initial_sent` and `quic_timeout_no_reply`; **no first peer datagram** was registered. Hence no header classification, peer-reply recheck, stable 3/3 candidate, actual H3 GET or anonymous browse API POST.
- Same fingerprint had previously shown rare peer replies at indices 0/1 and one separate verified handshake at index 3, but none were stable across runs.

## Conclusions and uncertainty

DNS failure and universal Xray protected UDP breakage are **not** supported by these controls. The observed failure depends on host/IP/path/protocol/timing; intentional filtering cannot be established from this experiment. The indexed A records do not disclose the public IP addresses, so destination-specific comparisons remain coarse. The diagnostic is not an application playback test.

## Next v0.7.66 experiment

Only when *no YouTube QUIC v1 address* passes the existing 3-of-3 handshake rule, perform an **additional independent QUIC version 2 (RFC 9369) first-pass** on the same pinned indexed IPv4 addresses, using the same original verified SNI and protected UDP/443 Xray socket adapter. Include before/after fixed `www.google.com` QUIC v2 controls on its previously verified Google DoH IPv4 answer set. Version 1 is explicitly pinned in its own handshake tests so the two cases are comparable. No custom UDP socket, DNS fallback, live VPN route or AUTO preference change.

QUIC v2 is *diagnostic only* in this build: neither a one-off v2 success nor a v2 response can authorize HTTP/3, and it never becomes positive AUTO/neural training evidence. If the two Google v2 controls fail, negative YouTube v2 outcomes are **inconclusive**; a failed server v2 handshake may indicate an unsupported version, not filtering. The complete experiment must still complete before the five-minute YouTube A-address TTL; exceeded TTL skips remaining trials. Do not report raw IPs, packet data, credentials or content.

After CI and signed test APK publication, repeat on the actual MOBILE network. Compare v1 outcomes, Google v2 pre/post, per-index YouTube v2 and the bounded HTTP/3 counts. Successful QUIC transport does not demonstrate usable video or YouTube feed.
