# DPpass 0.7.64 MOBILE — Google QUIC control verified, YouTube H3 unavailable

- Observed: 2026-11-23 10:56:45 +03:00, network MOBILE, on-device Android.
- YouTube DoH: verified private Google DoH A-only; HTTP 200; 8 sorted IPv4 indices; fingerprint `6f706c12` (unchanged from the earlier scan).
- Same-run Google `www.google.com` control: protected QUIC/TLS 1.3 with ALPN h3 **verified both before and after** YouTube trials (2/2). This supports that the Xray protected UDP probe transport can operate on this network.
- YouTube `youtubei.googleapis.com` per-index trials: 0/8 QUIC TLS 1.3/ALPN h3 handshakes verified. Index 1 returned at least one UDP datagram but the handshake timed out after 5001 ms (`quic_timeout_after_reply`, `quic_peer_reply`). Indices 0 and 2–7 timed out after an Initial without any registered reply.
- No candidate passed the required 3/3 independent handshakes, so no HTTP/3 GET or anonymous browse API POST ran.
- A previous scan with the same A-set fingerprint registered peer reply at index 0 (not index 1); one earlier separate scan had a single verified handshake at index 3. None of these is stable H3/API evidence.

## Interpretation

The common protected UDP adapter and Google DoH both work in the tested circumstances, but the eight YouTube endpoint probes do not. This pattern is consistent with **destination-, route-, or traffic-dependent behavior**, but does not distinguish intentional filtering, congestion/loss, CDN/backend handling, or packet/probe implementation behavior. A peer UDP reply is not proof of a valid QUIC Initial, Retry, Version Negotiation, ServerHello or TLS-certificate verification. The report does not contain packet headers, so their cause cannot be inferred.

## v0.7.65 follow-up

- Record **only the public QUIC v1/v2 packet-header class of the first UDP datagram** on that exact protected probe socket: Initial, Handshake, Retry, Version Negotiation, short, other long, unrecognized. Header shapes are not authenticated and do not establish a completed handshake. No CID, packets, raw IP, token, payload, or certificate is logged.
- Recheck at most **two** YouTube indices with a failed first handshake but a peer reply, **one more time** each for evidence only. They **cannot** become stable 3/3 candidates after an initial failure.
- Retain two same-run Google QUIC controls, fixed host/IP-family/DNS, three-success candidate rule, five-minute A-set expiration and opt-in/no-persistence/no-live-VPN-modification protections.
- Signed `0.7.65-dev` experimental ARM64 build requires CI and another actual MOBILE field test. Even a successful HTTP/3 response would not prove working video playback or the full YouTube app feed.
