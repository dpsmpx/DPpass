# DPpass 0.7.63 MOBILE YouTube API protected QUIC + HTTP/3 retest

- Report time: 2026-11-23 10:10:11 +03:00.
- Underlying transport: MOBILE; opt-in protected Xray UDP/443, exact SNI and Host `youtubei.googleapis.com`.
- Google DoH A-only: HTTP 200, 8 verified public IPv4 answers, sorted answer-set fingerprint `6f706c12`.
- First-pass QUIC handshakes: 0/8. IPv4 index 0 received a UDP peer reply but TLS 1.3/ALPN h3 handshake did not complete within 5 seconds (`quic_timeout_after_reply`); indices 1–7 timed out with no reply observed.
- There were no independently verified three-success IP candidates; no HTTP/3 GET or anonymous API POST was attempted.
- A prior v0.7.62 MOBILE probe had one verified QUIC/ALPN h3 handshake at IPv4 index 3. This run did not reproduce it; neither result demonstrates HTTP/3 request completion, working YouTube feed or video playback.

## Interpretation

The DNS operation completed, so failure occurred beyond DNS. A peer UDP datagram is not proof of a QUIC ServerHello, trusted QUIC/TLS handshake, HTTP/3 or API success. Eight timeouts do not alone distinguish path-dependent filtering, congestion/packet loss, DNS/CDN changes outside this fingerprint or a transport implementation issue. No same-run Google QUIC control was included in the 0.7.63 dedicated H3 experiment.

## Follow-up diagnostic implementation

A protected Google QUIC control at a verified DoH A record is now sampled immediately before and after the YouTube probe. The report marks incomplete or failed controls as inconclusive for YouTube-specific filtering. Control and target keep separate fixed SNI/Host, original protected Xray UDP socket adapter, unchanged live VPN, global DNS and AUTO/neural weights. The YouTube admission rule remains three independent verified h3 TLS handshakes; HTTP/3 GET and anonymous POST remain gated on that rule.

## Field verification still required

Build checks and localhost HTTP/3 integration tests are not evidence of successful YouTube connectivity on the MOBILE network. Repeat the opt-in H3 experiment on an actual Android device and compare Google QUIC before/after with per-index YouTube outcomes. Record only sanitized indexed results; do not collect raw IPs, response payloads, cookies or credentials.
