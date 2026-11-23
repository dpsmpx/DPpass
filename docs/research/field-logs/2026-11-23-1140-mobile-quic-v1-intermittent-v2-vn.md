# DPpass 0.7.66 MOBILE — transient YouTube QUIC v1; QUIC v2 control Version Negotiation

**Observed:** 2026-11-23 11:40:47 +03:00; mobile Android VpnService; fixed protected Xray UDP/443 probes.

## Reported evidence

- Google private authenticated DoH for `youtubei.googleapis.com`: HTTP 200; eight A-only indexed IPv4 addresses; sorted-answer fingerprint `6f706c12`.
- Same-run `www.google.com` protected QUIC v1 control: TLS 1.3 + ALPN h3 **verified 2/2**, before and after the YouTube scan.
- YouTube QUIC v1 first pass: **one TLS+ALPN h3 verified handshake**, at sorted index 1, elapsed 139 ms. Its second independent handshake timed out after sending Initial with no reply (5001 ms). Other seven indices each timed out without peer reply (about 5001–5002 ms). **Across all nine v1 attempts: 1 success**. No index achieved 3/3.
- Google QUIC v2 controls before and after both timed out after receipt of a public **Version Negotiation**-shaped packet; neither v2 handshake completed TLS. This is consistent with the destination/control path not negotiating v2, but the unauthenticated public-header classification does not prove which peer originated the datagrams.
- YouTube QUIC v2: 0/8 handshakes verified, all timed out with no peer reply; without a positive Google v2 baseline, these negative results are **inconclusive**.
- HTTP/3 GET and anonymous POST were **not attempted** because the v1 3/3 admission rule did not pass.

## Interpretation

At least one `youtubei.googleapis.com` endpoint on this MOBILE network *can* complete a verified QUIC v1 handshake, but this was not repeatable in the second independent connection. An absolute claim that all YouTube QUIC v1 handshakes are prevented is contradicted. A mixture of destination/path/flow-sensitive behavior, transient packet loss, endpoint changes or probing behavior remains possible; deliberate traffic filtering is **not established**. The same DNS answer-set fingerprint does not guarantee a permanent mapping of indices to physical backends.

## Follow-up in 0.7.67-dev

- For any IP index with a verified first QUIC v1 handshake, complete the **third independent** v1 handshake even if the second timed out. Record 1/3 vs 2/3 vs 3/3; only three verified distinct-numbered independent samples (1,2,3), matching fixed target and protocol, authorize any H3 GET. No `1/3` or `2/3` candidate is promoted.
- If no verified-v1 candidate exists and Google QUIC v2 pre-control cannot complete verified TLS 1.3/ALPN h3, **skip the eight-address YouTube v2 matrix** rather than treating an unverified v2 baseline as evidence. A bounded Google v2 post-control still documents whether the baseline changed.
- Keep private pinned DoH, protected Xray UDP/443, fixed SNI/certificates, bounded no-credential requests, five-minute native RRset TTL, no routing/strategy/global DNS/AUTO/neural learning updates.
- Release build and real-device retest required; unit tests prove algorithmic outcomes but not real YouTube feeds/videos.
