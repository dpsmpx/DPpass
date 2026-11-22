# One-button multi-site HTTPS diagnostic for AUTO-first Zapret2 (D-119)

## User experience

In experimental **Zapret2 VpnService**, the main user-facing DPI mode is
**AUTO**. The manual TCP strategy picker and the obsolete standalone A/B
screen/toggle have been removed from Android settings; lower-level modes
remain available to the **single integrated diagnostic button**.
The QUIC→TCP switch, unmatched HTTPS handling, hostlist, and root backend
are still available. Existing subscription functionality is untouched.

Choose **Settings → Zapret2 → Diagnose Google and YouTube** while VPN
is connected. Opening the diagnostic screen starts the run without a second
button press. It displays the current target, strategy and attempt, plus a
0/48 progress bar. On completion it displays the full report, copies it
to Android's clipboard and shows a completion message. If clipboard
writing fails the result stays selectable on screen. Leaving the
diagnostic screen cancels subsequent probes, with no false "complete" toast.

## Network behavior

The test sends exactly **48** bounded HTTPS requests from inside Xray:
three targets × eight protected TCP variants × two attempts.

| Target ID | Exact fixed target | Verification |
|---|---|---|
| `google_final` | `https://www.google.com/` | Valid TLS X.509 certificate, HTTP 2xx, Content-Type text/html and HTML start marker. This is the known destination after the original `google.com` 301; it is requested directly rather than redirect-followed. |
| `youtube_home` | `https://www.youtube.com/` | Valid TLS, HTTP 2xx, Content-Type text/html and HTML marker. An HTTPS page is **not** the app feed/API. |
| `youtube_thumbnail` | `https://i.ytimg.com/vi/jNQXAC9IVRw/hqdefault.jpg` | Valid TLS, HTTP 2xx, Content-Type image/jpeg, JPEG magic bytes and at least 128 response bytes. This checks a public thumbnail, **not** video stream transport from googlevideo.com. |

Strategies include `plain` (baseline), `split-1`, `split`,
`tlsrec-split`, `fake-3`, `fake-5`, `disorder`, and `auto`.
Each request is limited to an 8-second timeout and the first 8 KiB of body.
Requests are **not redirected** to new hosts. Google and YouTube can
reply with 3xx for consent/regional reasons; this yields `redirect`,
which is a real verified HTTP response but **not** successful content.

The private Xray test outbound for each strategy shares the DNS policy
and protected socket dialer used by the live VPN, but cannot be selected
by regular routing rules. A run never switches the current VPN strategy
or restarts the tunnel. TCP/HTTPS only; QUIC, HTTP/3, signed YouTube app
APIs and streaming video segments are outside this test.

## Outcomes and safety limits

- `ok`: 2xx with verified HTML/JPEG body signature and expected content type.
- `redirect`: 3xx from the requested host; not counted as content success.
- `http_status`: other HTTP statuses, including 403/404.
- `content_type_mismatch` / `content_invalid`: 2xx without expected content.
- `dial_failed`, `timeout`, `tls_failed`, `tls_ca_failed`,
  `request_failed`, `http_failed`, `body_failed`, `empty_body`.
- `invalid_target`, `invalid_strategy`, `invalid_timeout`,
  `engine_off`, `unsupported`, `contract_error`: diagnostic prerequisites/errors.

No arbitrary URL input is accepted by the Go bridge. The native result
contains only fixed outcome codes and numeric HTTP status, limited byte
counts, elapsed time and **process-wide** applied/skipped counter deltas.
No response bytes, IP addresses, domains contacted by other apps or
URL history are written into journal messages. The clipboard report
contains only this fixed catalog and its numerical test results.

The report groups outcomes by **target and strategy** and includes
all 48 individual attempts. It displays an exact median among successful
content checks (including *.5 ms when needed). Because mobile latency
varies and two samples are sparse, it must not automatically announce
a winning DPI strategy or equate Google/thumbnail success with YouTube
app feed/video availability.

## Field validation still required

The previous field logs proved only HTTP 301 for `google.com` across
all strategies. Re-run the expanded test on MOBILE and Wi-Fi, verify
clipboard auto-copy and retention of the live VPN, and report whether
YouTube's feed and video actually load. No DPI bypass success is claimed
before that physical validation.
