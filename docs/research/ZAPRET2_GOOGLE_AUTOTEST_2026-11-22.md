# One-button Google HTTPS strategy autotest (D-119)

**Goal:** reproduce a deterministic, browser-free HTTPS check for all available
rootless Zapret2 VpnService TCP strategies and copy the complete result with
one tap. This does **not** imply that YouTube works; previous field testing
showed YouTube did not load even text.

## Usage

1. Activate the experimental **Zapret2 → VpnService** backend and connect the VPN.
2. Open **Settings → Zapret2 · Test all strategies on Google**. The first tap
   opens the progress screen and **starts automatically**, no separate
   start button needed.
3. The screen displays the current mode and attempt, progress from 0/16
   to 16/16 and a report once complete.
4. After all 16 attempts, Android's ClipboardManager receives the **entire**
   plaintext report. DPpass shows **“Test complete. Full report copied to
   clipboard.”** If access to the clipboard fails, the result remains
   selectable on screen with an explicit error message.
5. The screen also has a button to rerun all tests. Leaving the screen
   cancels the remaining attempts and does **not** copy a partial report.

## Technical contract

- Target is **hardcoded** to `https://google.com/`; an authenticated TLS
  connection performs `GET /`, requires a valid X.509 certificate, and
  reads at most **8 KiB** of response body. A 3xx redirect is reported
  without following it: the test stays on google.com.
- Outbounds registered in serverless Xray config are used exclusively
  by a forced internal `core.Dial`. No routing rule refers to them,
  and the active VPN strategy, tunnel and serverless routing remain
  unchanged. The Android protected-socket hook is preserved.
- Strategies per round: `plain` (control), `split-1`, `split`,
  `tlsrec-split`, `fake-3`, `fake-5`, `disorder`, `auto`.
  There are two rounds per strategy: **16 attempts**, each bounded
  by **8 seconds**. These are the selectable VpnService TCP modes
  plus one control. Root-only nfqws2 profiles and QUIC UDP tricks
  are **not** tested by a TCP HTTPS probe.
- Result fields: `outcome`, HTTP status, body bytes, elapsed milliseconds,
  process-wide `applied_delta` and `skipped_delta`. The deltas may include
  concurrent connections and **are not** per-probe proof that the trick was
  applied. A `redirect` confirms TLS+HTTP response but not that
  the redirected site works. A response of `ok` needs 2xx plus nonempty
  body.
- The native JNI contract returns a compact `v1` tab-separated record
  with only fixed outcome codes and numbers. It never returns the fetched
  content, user DNS names, IP addresses, TLS keys or raw errors.
- Experimental test outbounds are created **only** when serverless
  desync and TUN are enabled; regular subscriptions retain their config.
  If the engine is off or the VPN mode is incorrect, the screen refuses
  to run rather than silently testing an unrelated network path.
- Running a test generates **intentional traffic** to Google. Normal web
  content outside Google is never fetched by the probe. A successful
  Google response does not establish a working YouTube feed or video.

## Classification

| Native status | Interpretation |
|---|---|
| `ok` | Verified TLS + 2xx + some HTTP body content |
| `redirect` | Verified TLS + 3xx HTTP response, redirect not followed |
| `dial_failed`, `timeout` | No complete result within TCP/connection timeout |
| `tls_failed`, `tls_ca_failed` | TLS handshake or certificate failed |
| `request_failed`, `http_failed`, `body_failed` | Failure during HTTP exchange |
| `http_status` | HTTP 4xx/5xx (server responded, test still failed) |
| `empty_body` | 2xx response with no returned content |
| `engine_off`, `unsupported`, `contract_error` | Prerequisite/API problem, not a DPI verdict |

**Follow-up:** If all TCP variants fail, inspect the existing
`zapret2_stage_window` data and compare DNS/DoH to isolate IP-level
blocks. If Google succeeds but YouTube remains blank, the failure is
site-specific and cannot be inferred from a Google-only probe.
