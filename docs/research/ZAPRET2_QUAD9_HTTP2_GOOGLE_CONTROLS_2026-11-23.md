# DPpass 0.7.62-dev — Google controls and Quad9 DoH HTTP/2

## Field evidence (23 November 2026, mobile network)

The user tested 8 A records resolved for `youtubei.googleapis.com`. The v0.7.61
matrix attempted 48 TCP handshakes (HTTP/1.1 and HTTP/2, three TCP modes)
and eight QUIC handshakes. No tested TCP connection observed a TLS server
reply; no QUIC peer datagram was observed. The Quad9 DoH endpoint returned
HTTP 505 with HTTP/1.1 despite completing the TLS connection.

Those observations alone cannot distinguish site-specific filtering from
generic failure in the private Xray socket, UDP tunnel, network routing or
probe instrumentation.

## Changes

- Quad9 DoH now explicitly negotiates ALPN `h2` over the same pinned
  `9.9.9.9:443` private protected Xray TCP socket, with full TLS server
  identity and certificate validation. It sends RFC 8484 binary DNS via
  HTTP/2 POST; Cloudflare and Google retain their earlier HTTP/1.1 path.
  Report numeric HTTP status and `doh_h2_not_negotiated` /
  `doh_h2_failed` errors separately. No unprotected fallback.
- Add a fixed Google control `www.google.com` resolved through pinned
  authenticated Google DoH, then TLS/HTTP/1.1, TLS/HTTP/2 and QUIC ALPN
  `h3` tests over the SAME exact protected TCP/UDP Xray test outbounds
  and instrumentation used for YouTube. Bound to the first two sorted,
  public IPv4 A answers and the plain baseline strategy. The Google
  controls run before the existing full YouTube address matrix.
- Record per-probe TLS EOF, TCP reset, socket closed and timeouts using
  distinct fixed status codes, including whether any peer bytes arrived.
  No raw OS error strings, URLs, IP addresses or payloads are serialized.
- The clipboard report shows separately the results for the Google control
  and the YouTube API. If the control fails, it explicitly refuses to infer
  YouTube-specific blocking. If Google works and YouTube does not, selective
  destination/SNI filtering becomes plausible but is still not proven.
- Existing application DNS, VPN routing, neural strategy weights and AUTO
  preference are not modified. No tests start automatically. The QUIC
  test checks the handshake only, **not HTTP/3 GET or video playback**.

## Validation

Go tests cover allowed hostnames/targets, the exact Quad9 HTTP/2-only mode,
an actual localhost HTTP/2 DoH POST over certificate-verified TLS,
zero DNS message ID, local EOF before peer bytes, simulated reset/close,
TLS timeout/alert and UDP remote address confinement.

Kotlin unit tests check v1/v2/v3 JNI compatibility, new fixed error codes,
Google/YouTube report separation, positive controls, failed controls
that do *not* trigger filtering conclusions, and absence of raw IPs.

GitHub Actions compiles Go/Xray Android components, runs all JVM tests,
assembles signed `arm64-v8a` APK (experimental certificate, versionCode
140) and publishes only after the signing and APK identity checks pass.

## On-device experiment

Use active experimental serverless VpnService and select
**Compare Google / YouTube: TLS, QUIC and IPv4**. Send the entire clipboard
report after the run. The test may require minutes on mobile networks.
Observe especially `control=www.google.com`, `Google control totals`,
`YouTube API totals`, Quad9 `doh_http` and `tls_eof*` /
`tls_reset*` versus `timeout_tls_no_reply`.

CI cannot establish real-device YouTube reachability. Keep the dependent
pull request in draft until the Android field report is reviewed.
