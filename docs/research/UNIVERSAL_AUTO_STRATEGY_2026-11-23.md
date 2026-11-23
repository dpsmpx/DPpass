# DPpass: universal, network-aware automatic strategy selection

Research date: 2026-11-23. Implementation branch: `feature/zapret2-auto-any-host-health-20261123`. This is a staged proposal; only the small passive circuit-breaker described under **Implemented** is enabled. No claim of universal successful unblocking or HTTP/3 playback is made.

## 1. Evidence from actual MOBILE testing

At 2026-11-23 12:31:31 +03:00, `youtubei.googleapis.com` returned the same private verified DoH A-set fingerprint `6f706c12`, with eight indexed IPv4 addresses. Google protected QUIC v1 controls verified **2/2**, before and after. YouTube QUIC v1 succeeded once, at index 2 after **162 ms**, and then timed out twice at that same index. The seven other first attempts failed with no peer datagram. **No address met 3/3**, so no HTTP/3 GET or anonymous browse POST was attempted. Google v2 twice produced only Version Negotiation-shaped public headers without successful TLS, and the new v2 pre-control gate correctly skipped the YouTube v2 matrix.

Prior observations at indices 1 and 3 likewise showed brief QUIC v1 success followed by failure. These measurements disprove an absolute inability to establish YouTube QUIC v1, but they **cannot** identify a DPI signature, carrier policy, backend instability or path packet loss. A timeout after a QUIC Initial is not an HTTP-level failure. A TLS handshake is not a video feed or playback.

## 2. Research: what to reuse, and what not to assume

1. **bol-van/zapret2 blockcheck2**: tests by strategy families, allows repeated attempts and multiple target domains, distinguishes quick scan from exhaustive scan, warns about rate limiting and non-deterministic middleboxes. Adapt the **measurement hierarchy and repeated independent trials**, not its raw OS packet injection: rootless Android does not have access to Linux NFQUEUE, and DPpass has a different protected Xray socket pipeline.
   - https://github.com/bol-van/zapret2
   - https://git.stdev.su/Mirrors/bolvan-zapret2/src/commit/99a7f069767c24b48e1f1ad1a74c3d02d5fba3f2/docs/manual.en.md
2. **Zapret2 AutoHostlist**: uses TCP retransmission, early resets, suspicious redirects and UDP send/receive imbalances, plus a failure threshold and time window. Adapt the **bounded failure counter and observation feedback loop**; do not turn absence of a response into a definitive block verdict, and avoid global hostlist writes without consent.
   - https://github.com/bol-van/zapret2/blob/master/config.default
3. **sing-box URLTest, Mihomo url-test/fallback**: make selection based on health and latency; tolerate small fluctuations, do not terminate existing connections, provide a deterministic fallback, and test only when needed. A generic Google 204 success proves one route works, **not that YouTube, a bank, a CDN or an API works**. Prefer per-service probes.
   - https://github.com/SagerNet/sing-box/blob/testing/docs/configuration/outbound/urltest.md
   - https://wiki.metacubex.one/en/config/proxy-groups/
4. **dpifuzz**: constraint-aware, asynchronous parameter exploration with memoized measurements and stopping when apparent gains lie within noise. Useful for offline/manual Zapret2 profile discovery, but not as an unlimited background scan of arbitrary websites.
   - https://github.com/CosmicIndustries/dpifuzz
5. **Happy Eyeballs RFC 8305**, and draft Happy Eyeballs v3: bounded, paced alternative connection attempts, never uncontrolled parallel traffic. **RFC 9002** QUIC PTO and retransmission mean that a 5-second timeout may hide different loss patterns. **RFC 9369** QUIC v2 is not inherently a bypass; Version Negotiation without verified TLS is an inconclusive negative control.
   - https://www.rfc-editor.org/rfc/rfc8305
   - https://datatracker.ietf.org/doc/html/draft-ietf-happy-happyeyeballs-v3-05
   - https://www.rfc-editor.org/rfc/rfc9002
   - https://www.rfc-editor.org/rfc/rfc9369
6. **Android VpnService and NetworkCallback**: protect and bind underlying sockets, avoid tunnel loops, respond to network/link changes asynchronously; a probe must follow the selected transport path. **RFC 9460** HTTPS/SVCB and ECH affect service address/protocol selection; an SNI-only selector cannot identify every encrypted or IP-only flow.
   - https://developer.android.com/reference/android/net/VpnService
   - https://developer.android.com/reference/android/net/ConnectivityManager.NetworkCallback
   - https://www.rfc-editor.org/rfc/rfc9460

## 3. Proposed layered selector

### Stage A — identify context without collecting browsing history

Key an **in-memory** decision by network generation, exact destination hostname (only when known from a permitted DNS/SNI/Host context), transport (`tls-tcp`, `http-tcp`, `quic-udp`), address family, and *candidate route*. Use the original hostname for certificate validation even if the destination IP is pinned. Do not infer a hostname from arbitrary encrypted contents. Keep connection-specific decisions fixed for their lifetime. Existing code uses exact host keys with separate `http:` and `udp:` namespaces; it resets on reconfiguration/network change and does not persist visited hosts. Avoid merging subdomains or unrelated CDNs without proof of shared policy.

### Stage B — separate route choice from packet strategy

Treat these as different dimensions:
- route: user-approved **direct**, **local Zapret2**, or **an eligible subscription server** (chosen by existing server health/eligibility rules);
- transport: TCP/TLS vs QUIC, IPv4/IPv6, or standards-compliant application fallback when technically possible;
- local Zapret2 candidate: `pass`, `split-1`, `split`, `fake-3`, `fake-5`, `disorder`, `tlsrec-split` on TCP; approved, transport-specific profiles on UDP;
- app/site: SNI/Host when visible; group multi-host services only with an explicit manifest (homepage, API, CDN, thumbnails) and independent validation.

A working node at a global 204 URL must **not** overwrite a pinned user server or imply it serves all destinations. Existing manually selected routes or profiles always win over AUTO.

### Stage C — evidence hierarchy, not generic ping

`DNS valid` → `TCP connected / UDP Initial sent` → `certificate-verified TLS / QUIC ALPN` → `real HTTP response` → `bounded expected content` → `sufficient useful downstream bytes` → `application-level success`.

Never promote a strategy on DNS alone, server reply bytes, TLS handshake alone, anonymous API 4xx, or one transient H3 attempt. Do not interpret 204 on an unrelated control as site success. Some authenticated apps cannot be tested without credentials: in those cases keep a **transport-only/inconclusive** label and use only passive, aggregated connection observations. ECH and IP-only apps may require an IP-scoped coarse policy or user-defined routing rule, rather than invented domain attribution.

### Stage D — bounded candidate trial / stop rules

- First test the untouched path (on demand, when safely testable), then a small set of conservative profiles. Do not test every possible TTL or every node on every request. Use **2–3 independent observations** before claiming reliability; a 1/3 handshake is intermittent, not healthy.
- Measure both success probability and latency, but optimize success **first**; a fast 139 ms transient handshake loses to a slower but stable path.
- Use a sliding window or decayed, bounded per-context score. Prefer an established winner and use hysteresis to avoid route flapping; if no candidate clears the confidence threshold, report inconclusive instead of selecting a random "winner". Neural scores are merely priors, never substitutes for verified transport/content evidence.
- Cap concurrent probes, total bytes, per-host attempts and time, with exponential backoff and jitter. Skip background scanning on metered networks/battery saver; keep periodic checks idle by default. Respect service rate limits and do not replay app cookies or private URLs.
- On 2 explicit **first-reply TLS ClientHello or QUIC Initial read timeouts** for one host+protocol+candidate, temporarily deprioritize **that candidate only**, not every site nor the whole network. A benign application close must not count. Use a short cooldown; re-enable automatically afterward or after a meaningful successful response. Never terminate established streams to force a new strategy.

### Stage E — host-aware live fallback

AUTO may change the technique for **new** connections only. For failed connections, reschedule after independent evidence and a cooldown; do not silently replay POSTs/other non-idempotent user requests. A fallback to a subscription server is permitted only when the user has enabled that fallback and the server is healthy/eligible. Do not alter global DNS, VPN on/off, selected route, or manual pins as a side effect of a test.

### Stage F — diagnostics, transparency, privacy

One bounded local report: current network category, kind of connection, attempt counts, coarse phase and strategy ID, candidate confidence and reason, without raw IP/host unless the user explicitly requests a per-site report. Do not export visited domains or neural sparse keys. Always show when no route is verified. Keep a manual override and a rollback switch; health reports are not proof of censorship.

## 4. Implemented now: passive per-destination cooldown

The existing Go `adaptiveSelector` already chooses candidates for new TCP SNI/HTTP Host and QUIC IP flows and uses a local neural prior. This first patch adds a strictly memory-only **circuit breaker**:

- **Trigger:** 2 separate protected TCP `desyncConn.Read` first-reply timeouts after a sent TLS ClientHello, **or** UDP `desyncUDPConn.Read` timeouts after a sent QUIC Initial without a first reply, for the same exact host/IP key, transport namespace and technique. Ordinary UDP closures or socket writes alone do not qualify. The per-connection atomic guards on TCP and QUIC ensure a timeout is not counted twice during Close.
- **Action:** suspend only that technique for **90 seconds** for that host; a candidate of the same name on another host or another transport is unaffected.
- **Recovery:** after expiration, or after `>=12 KiB` observed downstream on that same technique, the candidate becomes eligible again. Only explicit read-timeouts set the breaker; short HTTP responses, a benign zero-byte Close or a TCP dial failure do not falsely trigger it.
- **ML safety:** the existing neural prior cannot pick a temporarily suspended candidate; no neural architecture, weight persistence schema, server subscription, manual route, DNS, Xray outbounds or live VPN selection controls are modified.
- **Memory safety:** limited by existing 1024-host in-memory cache, bounded current candidate names, and reset on network/session reconfiguration. No visited domains, packet data, credentials, IP addresses or health results are written to a file.
- **Tests:** independent host; TCP/UDP isolation; 2-timeout threshold; cooldown expiration; no stale old-network observation; no cooldown from ordinary Close; matching downstream success restores only its own method; localhost protected-adapter-equivalent QUIC Read timeout is not double counted on Close.

This is a conservative **first phase**, not full automatic arbitrary-site HTTP verification or universal website bypass. Further active tests, server failover and cross-network learning must be gated by design review, explicit user controls and on-device measurements.

## 5. Release acceptance gates

1. Go tests and Android/Kotlin JVM regressions pass on CI; signed ARM64 APK signature and embedded Alpine/PRoot assets validate.
2. Real Android tests on MOBILE and WIFI compare a normal reachable site, a blocked HTTPS site, a small API, an H3 endpoint, and optionally one user-approved subscription server; each has baseline and at least two candidate repetitions.
3. Show no more than one probe burst per site during a cooldown and no flow-affecting changes after connection establishment.
4. Verify no private DNS bypass, arbitrary HTTPS URLs, unknown-IP raw logging, credential copying, background scanning or automatic route override. Reject release if any of these regress.
5. Keep this code in a draft PR; merge after positive tests or under a deliberately disabled-by-default experimental switch.

## Priority roadmap

- **P0** now: memory-only per-host/per-protocol circuit breaker and tests.
- **P1**: on-device connection-classifier telemetry with explicit `timeout/peer-reply/TLS/http/content` evidence and typed outcomes; separate TCP/UDP/IPv4/IPv6 and network generations. Never train from mere connection completion.
- **P2**: opt-in **user-specified domain / service** test planner (all safe domain names, not arbitrary full URLs), bounded protected DNS+TLS+HTTP GET/HEAD when authorized and expected, with TLS verification. Generic 4xx is transport only.
- **P3**: per-site candidate confidence with windowed scoring and hysteresis; test untouched baseline before tricks; optional cross-domain strategy family hints only after repeated exact-host outcomes.
- **P4**: route-level fallback among user-enabled direct/Zapret2/eligible servers with server-specific health, explicit manual overrides, no silent replay of non-idempotent traffic.
- **P5**: constrained offline Zapret2 profile search for consenting targets and supported protocols; no generic global mutation/indefinite fuzzing. QUIC-to-TCP fallback is app-dependent, not universally controlled by a VPN.
