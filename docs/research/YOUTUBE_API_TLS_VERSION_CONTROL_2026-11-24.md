# DPpass 0.7.74 — isolated TLS 1.2 vs TLS 1.3 same-IP, same-SNI controls

## Grounded real MOBILE results (0.7.73)
- Eight public IPs from certificate-verified Google DoH for `youtubei.googleapis.com`.
- Same-IP matched `plain`, HTTPS/HTTP1.1: API SNI = 0/3 on each of first 2 IPs, but `www.google.com` SNI = 3/3 on those same IPs; the other 6 IPs each show 0/1 API and 1/1 Google. Independent Google own-DNS control completes TLS and HTTP 200. All certificates were verified.
- This is a repeatable **hostname-dependent** difference. It supports SNI-specific filtering or service policy differences, but cannot prove what device caused it. The YouTube app does not refresh its feed, despite old shorts previews and separate i.ytimg.com JPEG success.
- Seven previously tried TCP strategies (including lossless TLS record splitting within SNI and fake-5) have not completed a single API TLS handshake. All 8 API IPs fail on both H1/H2 with the sampled candidates. Iterating the same profiles again is not useful.

## Opt-in matched protocol version experiment
- UI: "Сравнить TLS 1.2 и 1.3 для YouTube API (диагностика)".
- One authenticated public Google DoH A-record set, first TWO pinned IPv4 only.
- Two TLS versions, **forced exact MinVersion=MaxVersion**: TLS 1.2 / TLS 1.3.
- Two authentic SNI and HTTPS Host identities on each identical IP: `youtubei.googleapis.com` / `www.google.com`.
- HTTP1.1, normal `plain`, original certificate checks, explicit SNI. No domain fronting or production route alterations.
- 2 IP × 2 versions × 2 identities × 3 independent sockets = **24 probes**, max 5 seconds each plus bounded DoH. Same Xray protected private test outbound, fixed public IP, no credentials/cookies, capped 256-byte body; no user URL or headers exported.
- If Google 3/3 vs API 0/3 for a version on one IP, the report says only "stable TLS hostname difference". If TLS1.2 unexpectedly returns API HTTP 2xx–4xx, that proves transport reachability only, **not** a working YouTube browse POST.
- All experiments are user-initiated and diagnostic-only. The verified native `siteSearchMayRecord` admission guard excludes them even when opening TCP fails. Global DNS, routing, UDP/QUIC, subscription selection, AUTO and neural weights never change.

## Follow-up and remaining uncertainty
Run on MOBILE, then optionally WiFi. Copy the redacted TLS version report with IP indices and TLS stages.
A 0/3 API result even under TLS1.2, while the same-IP Google 3/3, reinforces hostname-dependence but does not assign responsibility to DPI. If TLS1.2 succeeds, first repeat/validate and separately test actual YouTube app feed. This release does not claim to restore the feed or video playback; leave PR draft and main unchanged.
