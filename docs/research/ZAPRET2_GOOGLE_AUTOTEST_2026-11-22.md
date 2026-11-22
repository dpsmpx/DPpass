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
content checks (including *.5 ms when needed).

### Provisional exact-host learning for AUTO

In the mobile field test, `www.youtube.com` timed out twice under
`plain` but returned verified HTML twice under `tlsrec-split` and
`fake-5`. Previously AUTO rotated through `split-1` and `split`
and timed out before reaching either working candidate.

AUTO now learns a **temporary, exact-host** preference while the
one-button diagnostic is running. It requires, within one sequential
test run, (1) two failures under plain (timeout/TCP dial/TLS failure),
and (2) two verified `outcome=ok` HTML responses for one of the six
manual TCP candidates. Redirects, partial content, a single success,
Google results, thumbnails, and results from the AUTO probe itself
**cannot** teach this preference. If multiple candidates qualify,
the lower sum of two elapsed times is only a provisional tie breaker;
two samples are too sparse for a global performance claim.

The preference applies to **new TLS connections** with the exact
`www.youtube.com` SNI in the current native process, not all of
`youtube.com`, `youtubei.googleapis.com`, `googlevideo.com`,
`i.ytimg.com`, arbitrary user domains, or QUIC. It is memory-only,
discarded on VPN/network reconfiguration, and withdrawn after two
very weak live responses. For these HTML-verified selections, the
weak-response threshold is 4 KiB rather than the media-oriented 12 KiB,
so a successful 8 KiB HTML sample cannot by itself undo the learning.
A known alternative may then be tried on a new connection; no in-flight
TLS stream is rewritten.

The AUTO attempts occur **after** the manual probes in the same test
and should exercise this temporary preference. This needs Android
field verification: an HTML response still does not establish
YouTube's mobile feed API or googlevideo media streaming.
The user-facing report shows the **eligible provisional candidate**,
not an assertion that live YouTube playback was fixed.

Because mobile latency varies and two samples are sparse, the
diagnostic must not announce a global winning DPI strategy or equate
Google/thumbnail success with YouTube app feed/video availability.

## Field validation still required

The early field logs proved only HTTP 301 for `google.com` across
all strategies. On **2026-11-22 21:46 +03:00**, the expanded MOBILE
test showed 16/16 verified Google HTML, 15/16 verified thumbnail JPEG,
but **0/2 AUTO YouTube HTML** versus **2/2 tlsrec-split** and
**2/2 fake-5**. The new learning is motivated by this contrast,
not by a claim of YouTube app success.

Re-run the expanded test on MOBILE and Wi-Fi, verify that the AUTO
YouTube HTML row changes appropriately after verified candidates,
clipboard auto-copy and VPN retention, and report whether YouTube
feed and video actually load. No YouTube app bypass success is claimed
before physical validation.
