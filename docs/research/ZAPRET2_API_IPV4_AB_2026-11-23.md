# DPpass 0.7.59: Google search and YouTube API diagnostic A/B (23 Nov 2026)

## Field observation

Android 15, MOBILE, active serverless VpnService, AUTO, QUIC→TCP=false.
96? **Original test had 64 attempts**: Google home 16/16 valid HTML;
YouTube home 6/16 valid HTML (tlsrec-split, fake-5, auto each 2/2);
youtubei.googleapis.com 0/16 with all TCP modes (8s timeouts);
i.ytimg.com JPEG 15/16. The real Google search UI and YouTube feed did
not load. No conclusion about app HTTP/2/QUIC or media is warranted from
the original HTTP/1.1-only probe.

The process-wide counters showed 85 IPv6 unreachable dials, 0
successful IPv6, 110 successful IPv4. This is strong evidence of unusable
IPv6 in the observed network, **not proof that IPv6 caused the HTTP/1.1
API failure**, because background apps also contribute and failures may
occur at TLS or HTTP stages.

## Controlled enhancement, no production routing change

- Add `google_search`: HTTPS GET to
  `www.google.com/search?q=site%3Aexample.com`. Only tests HTML delivery,
  **not** that a Google result page is useful, complete or rendered.
  A fixed public query avoids sending a user's query.
- Add `youtube_api_ipv4`: identical unauthenticated
  `youtubei.googleapis.com/youtubei/v1/browse` HTTP/1.1 GET with TLS
  certificate verification and the same TCP desynchronization strategy.
  Its **private test outbound** uses `sockopt.domainStrategy=ForceIPv4`;
  regular test and ordinary VPN outbound keep the configured DNS family.
  No automatic real-app routing change follows from a partial result.
- Replace ambiguous `timeout` with `timeout_dial`, `timeout_tls`,
  `timeout_write`, `timeout_headers`, and `timeout_body`. Parser and
  AUTO evidence preserve compatibility with old generic `timeout` codes.
- Report comparison of actual HTTPS responses received for configured
  DNS versus IPv4-only. On HTTP 400/403/404, only transport was reached;
  the real API, search results and feed remain unverified.
- Six fixed targets × eight candidates × two attempts = **96 HTTPS
  requests**, each with 8s limit. Their outcome is independent of
  ordinary VPN traffic. QUIC and app HTTP/2 remain outside scope.

## Interpretation for next device test

- If `youtube_api_ipv4` succeeds with a given strategy while the
  configured DNS equivalent fails, inspect address-family selection and
  consider an **opt-in** IPv4-preferred strategy rather than changing
  global routing without evidence.
- If both fail at `timeout_tls`, try other qualified transport methods
  or a provider VPN server and investigate site-specific DPI limitations.
- If `timeout_headers`, TLS succeeded and the HTTP server did not return
  headers, which requires distinct diagnosis.
- If Google search returns `ok`, that means an HTML signature at
  `/search` only; it does not validate result rendering.
- Do not promote a global "best" strategy from two samples or assume
  `www.youtube.com` HTML success implies `youtubei.googleapis.com`
  success. The IPv4 control does not contaminate native AUTO evidence.

Tests exercise Kotlin catalog/report and private outbound isolation,
native Go allowlist and TCP/TLS timeout classification. Field success
remains to be verified on the real network.
