# MOBILE 22.11.2026 22:12 +03 — AUTO HTML success; YouTube app still empty

User reported the 48-probe Google/YouTube/JPEG results and stated: **“ничего не загрузилось, хотя во время теста мне пришло уведомление с TikTok”**. The TikTok notification is not attributable to YouTube or to a proven unrestricted tunnel path; push notifications may be delivered independently of that app's full content path.

## Controlled HTTPS content probes

| Target | AUTO | Baseline plain | Other reliable modes |
|---|---|---|---|
| Google final HTML | 2/2, 508/453ms | 2/2, 570/490ms | All 8 strategies 2/2 |
| YouTube home HTML | **2/2, 1250/1372ms** | **0/2, 8002/8000ms timeout** | **fake-5 2/2 (1100/1205ms); tlsrec-split 2/2 (1591/1554ms)** |
| Thumbnail JPEG | **1/2, 292ms OK then 8001ms timeout** | 2/2 | split 1/2, others 2/2 |

All successes require a verified TLS certificate, HTTP 200 and recognizable HTML/JPEG prefix from up to 8192 body bytes. This is **not** proof of native YouTube application feed, YouTube Innertube API, QUIC or actual googlevideo video segment availability. The diagnostic did not test either of those services.

The report contained:
```
Provisional exact-host AUTO candidate: fake-5 for www.youtube.com
Native AUTO may temporarily prefer this tested method for new TLS connections.
Evidence: plain failed 2/2, fake-5 verified YouTube HTML 2/2.
```
This shows that the previous exact-host adaptive fix improved `youtube_home / auto` from 0/2 to 2/2. It **did not** fix the user's reported blank YouTube app. Do not apply this exact-host winner globally to `youtubei.googleapis.com`, `googlevideo.com` or other app services without their own evidence.

## VPN journal (same mobile session)

Android API 35, version 0.7.54-dev, Xray 26.9.30; Alpine socket probed and process alive; `rest=split`, `dns=doh`, hostlist `n=0`, `local_desync=auto`, `quic_force_tcp=false`, `https_unmatched=true`; underlying network MOBILE. The initial `ACTIVATION_REJECTED` was a deferred restoration event before successful `tunnel_up`/`connected` and is not evidence of a crash.

Observed 30-second windows UTC 19:12:53, 19:13:24, 19:13:54, 19:14:24, 19:14:55, 19:15:25, 19:15:55 and 19:16:26:

- `tcp_dial_ok`: 38, 29, 23, 59, 16, 21, 19, 22 (sum 227).
- `tcp_dial_unreachable`: 30, 20, 5, 15, redacted in remaining windows; **at least 70 known failures**. No IP-family distinction in this build.
- `tcp_clienthello_sent`: 35, 29, 23, 59, 16, 21, 16, 21 (sum 220).
- `tcp_first_reply`: 33, 23, 20, 56, 16, 21, 12, 19 (sum 200).
- `tcp_read_timeout`: 0, 0, 0, 0, 0, 0, 2, 1.
- `quic_initial_sent=0` across all windows; transport counters are scoped to experimental outbounds and cannot establish what other UDP paths did.
- Upstream/downstream bytes are process- or tunnel-wide and include background app traffic. In particular the large downstream windows do not imply YouTube loaded.

## Follow-up

The next build augments the one-tap diagnostics with an unauthenticated **YouTube API host TLS/HTTP reachability** target, separate from real API content, and divides unreachable TCP errors by IPv4/IPv6/unknown. Do not equate HTTP 400/403 with an authorized API call or assume IPv6 is the cause until measured. The next mobile result should be 64 attempts, with `youtube_api_transport` broken down by mode and address-family counters in the log.

A real YouTube app feed/video test still requires appropriately scoped API/media requests; a static googlevideo URL is not a valid proxy for a signed, dynamically allocated stream.
