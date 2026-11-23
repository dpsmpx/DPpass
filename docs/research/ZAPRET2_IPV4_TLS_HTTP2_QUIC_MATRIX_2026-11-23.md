# DPpass 0.7.61-dev: protected A-address TLS / HTTP2 / QUIC diagnostic

## Evidence behind this change

On 2026-11-23, a user's mobile-network fixed DoH comparison showed a
matching 8-address IPv4 RRset for Cloudflare and Google; `fake-5` and
`tlsrec-split` timed out in TLS for every sampled (first-address) attempt.
Quad9 returned `doh_http_status` but the numeric HTTP status was hidden.

The earlier test was not sufficient to rule out address-specific network
behavior because it checked only the first sorted A record for each attempt.

## New opt-in button

Use active **Zapret2 VpnService without a VPN server**, open the HTTPS
diagnostic screen, then press **Test all IPv4, TLS / HTTP2 / QUIC**.

1. Contact the same fixed DoH resolver IPs: Cloudflare 1.1.1.1,
   Google 8.8.8.8, Quad9 9.9.9.9. Full certificate validation and fixed
   hostnames; HTTPS POST, `application/dns-message`, DNS ID = 0 as RFC 8484
   requires. Report numeric HTTP errors from the resolver.
2. Store each verified A RRset temporarily inside the native process,
   tied to the running Xray instance and a ten-minute expiration.
   After fresh resolver checks, use only the existing protected private
   Xray test outbounds. No ordinary app DNS, routes or AUTO preferences change.
3. Sort the maximum 16 public unicast IPv4 addresses and test **every
   address index**. Never emit literal addresses, DNS raw data or HTTP
   response bodies. Equal eight-character fingerprints are treated as
   likely duplicate address sets to avoid extra mobile traffic, not proof
   against digest collisions.
4. For each address test protected TCP/443 with `plain`, `fake-5`,
   `tlsrec-split`, each offering HTTP/1.1 or HTTP/2 over verified TLS.
   Per-probe socket observation separates TCP dial, ClientHello sent,
   peer TLS bytes seen, full verified TLS and HTTP status.
   ALPN must negotiate `h2` for the HTTP/2 probe.
5. Also send a genuine QUIC v1 TLS 1.3 handshake over a separate protected,
   pinned UDP/443 connection with the original hostname and ALPN `h3`.
   This does **not** test HTTP/3 GET, YouTube video or the app feed. QUIC
   does not use TCP desynchronization methods.

Each address trial has a five-second deadline; DoH preparation has twelve
seconds per resolver. The number of attempts depends on the number of A
records and unique fingerprints, potentially **many minutes** on mobile data.
Leaving the screen cancels between requests; one in-flight JNI request may
run until its deadline. The report is copied to clipboard if permitted.

## Reading results

- `doh_http_status http=400`: the resolver returned a verified HTTP 400,
  not an established TLS block of YouTube.
- `timeout_tls_no_reply stage=clienthello_sent`: ClientHello sent, no peer
  bytes seen before deadline; compatible with selective network filtering.
- `timeout_tls_after_reply stage=server_reply_seen`: some peer bytes were
  seen, but the handshake was not verified; not proof of ServerHello.
- `tls_alert`: a TLS Alert record was the first peer reply.
- `tls_verified` + `h2`: the certificate chain and HTTP/2 ALPN succeeded;
  HTTP `2xx/4xx` proves unauthenticated transport only.
- `quic_verified`: valid QUIC handshake and certificate, **not** HTTP/3 or
  video playback.
- `quic_timeout_no_reply`: no QUIC peer datagram before deadline; could
  indicate network interference, packet handling, or server behavior.
- `dns_not_prepared`: no currently valid native address set was prepared
  for that resolver/session.

Do not set a persistent global DNS/strategy winner from these measurements:
DPI behavior, CDN routing, network type, TLS/QUIC fingerprints and background
traffic can change between runs.

## Reproducibility and test coverage

Go regression tests cover RFC 8484 zero ID, resolver question isolation,
strict matrix target allowlist, strategy/protocol combinations, v3 wire privacy,
ClientHello-without-reply vs TLS alert, and UDP destination confinement.
Kotlin unit tests cover v1/v2 compatibility, v3 validation, per-IP reporting,
DoH HTTP statuses, and preservation of anonymity in the clipboard report.
The signed Android GitHub Actions build must pass all included Go and Kotlin
unit tests, Gradle release assembly and certificate/version verification.

Real Android/mobile-network TLS behavior must be verified with a field report;
CI alone cannot prove YouTube will load.
