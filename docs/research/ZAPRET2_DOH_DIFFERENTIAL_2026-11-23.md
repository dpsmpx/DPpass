# 2026-11-23: Russian DNS interception vs YouTube API TLS stalls

## Evidence (Android 15, MOBILE, 0.7.59-dev)

- Cloudflare is the selected user DNS in serverless DoH mode.
- google.com / and /search HTML: 16/16 each, but the UI search was
  reported unusable. HTML prefix success does not prove rendered results.
- youtube.com HTML: 6/16 (QUIC→TCP off) and 5/16 (on), mainly fake-5
  and tlsrec-split. YouTube feed/API and media are still unverified.
- youtubei.googleapis.com on configured DNS: 0/16 verified HTTPS replies
  in both tests; IPv4-only control: 0/16 in both. All 64 API attempts
  reached TCP and stalled on the TLS handshake (timeout_tls).
- Process-wide Xray counters reported hundreds/thousands of unreachable
  IPv6 dials, zero successful IPv6, but those background-inclusive
  counters do not establish the cause of API TLS timeouts.
- Native strategy learning observations grew 13→46 with successful
  Android snapshot persistence. Merely increasing model parameters or
  training iterations cannot force a blocked TLS handshake to succeed.

## Why DNS should be tested separately

OONI research documents both deceptive DNS answers (NXDOMAIN or
censorship page IPs) and distinct post-connect TLS interference in
Russian networks. 2026 reports describe interception of UDP/53
destined for 1.1.1.1 and 8.8.8.8 and disruptions of DoH/DoT endpoints
in some networks. Provider, route, region and transport differ;
we do not infer blanket interception from one observation.

Merely changing the global DNS setting confounds the test and can
affect every app. Using UDP/53 as a supposed "Cloudflare" control
could instead reach an intercepted resolver.

## 0.7.60 opt-in protected comparison

- Separate button in the Zapret2 multi-site autotest. The original
  96-test suite remains unchanged.
- Four controls (configured-DNS IPv4 plus Cloudflare, Google and Quad9
  DoH), two proven YouTube HTML methods (fake-5 / tlsrec-split), and
  two repeats = 16 attempts, max 12s each.
- The three DoH servers are contacted via protected Xray test sockets
  to fixed IPv4 bootstrap addresses: Cloudflare 1.1.1.1 at
  cloudflare-dns.com, Google 8.8.8.8 at dns.google, Quad9 9.9.9.9
  at dns.quad9.net. Only TLS-verified POST /dns-query with binary
  RFC 8484 wire-format A queries for youtubei.googleapis.com is used.
- No plaintext DNS:53 is sent by these explicit controls. A resolver
  TLS/DNS failure is a doh_* code and not conflated with the HTTPS
  target's timeout_tls.
- Each DNS response is authenticated by the HTTPS certificate and
  checked for DNS question, transaction ID, RCODE, A/CNAME ownership,
  public IPv4 addresses, and strict byte limit. Neither raw IPs nor
  request bodies are returned over JNI. Report only count and truncated
  SHA256 of sorted A record set (8 hex characters). A collision is
  theoretically possible; hash equality is only diagnostic evidence.
- One sorted IPv4 from the received answer set is then dialed over a
  private ForceIPv4 test outbound. HTTPS SNI/Host remains
  youtubei.googleapis.com and the certificate is verified. This does
  not test every address in a DNS RRset.
- Normal application DNS policy, subscriptions, ordinary VPN routing,
  and AUTO host strategy learning are not modified by this diagnostic.
- No claim that a 4xx response to an unauthenticated GET proves a real
  YouTube API response, usable feed, playback or HTTP/2/QUIC access.

## Interpretation

- DoH `doh_timeout_tls`: that encrypted resolver is unreachable or
  handshake stalled; no inference about its answer set.
- DoH resolved with a fingerprint but `timeout_tls` at YouTube:
  encrypted DNS succeeded, but target TLS remains blocked/stalled on
  the selected IP.
- Different fingerprints may arise from legitimate geo-aware CDN
  balancing; do not label them poisoned unless independent evidence
  rules out normal DNS variation.
- One provider's HTTPS control succeeds and another's fails:
  candidate DNS/IP-routing difference. Test repeats, compare on the
  same cellular network, then consider an opt-in per-domain policy.
- All DoH-retrieved IP controls timeout_tls: changing the resolver
  alone will not recover the tested API path under current settings.
  Investigate host-specific transport methods, a VPN server route, and
  genuine app HTTP/2/QUIC separately.

Sources:
- OONI Russian censorship measurements:
  https://ooni.org/ru/post/2024-russia-report/
- OONI distinct DNS vs TLS fingerprints:
  https://ooni.org/post/2024-russia-report/
- Google Public DNS HTTPS API:
  https://developers.google.com/speed/public-dns/docs/secure-transports
- Cloudflare DoH:
  https://developers.cloudflare.com/1.1.1.1/encryption/dns-over-https/
- Quad9 secure DoH:
  https://quad9.zendesk.com/hc/en-us/articles/360056849272-Recommended-Secure-2-Service
