# DPpass Zapret2 AUTO — plain TCP baseline and first-reply timeout (2026-11-23)

## Evidence

A 2026-11-22 Android 15 MOBILE log shows Alpine socket and VPN TUN readiness,
but only partial YouTube title loading; feed pagination and video media
were not demonstrated. `connected` does not prove application-level success.

The earlier startup `ACTIVATION_REJECTED` severity race was already fixed
on main; `work_finished reason=activity_stop` is Activity lifecycle only.

## Changes

- Preserve the first five TCP DPI candidates and `tlsrec-split`, followed
  by a seventh `pass` candidate for direct, **unmodified TCP** in AUTO.
- HTTP/1 excludes TLS-record rewriting; its six candidates finish with
  `pass`. UDP/QUIC selection remains independent.
- Optional local 9-output neural models remain compatible. Plain TCP uses
  deterministic exploration and can earn a payload-backed per-host preference.
- An HTTPS TCP read timeout before any server reply immediately supplies one
  zero-byte observation for future connections. Close avoids counting that
  timeout twice, and a late payload can still update the outcome.
- The selector changes only future connections; live TLS is never rewritten
  mid-stream. Existing network-change resets and explicit host/IP selections
  remain intact.

## Required physical tests

On the real Android network, check YouTube feed pagination, thumbnails,
authenticated API, comments, actual googlevideo media, QUIC enabled/disabled,
selected host/IP behavior, and Wi-Fi/MOBILE transitions. Record stage and
transfer counters. A successful TLS handshake, an HTTP transport 2xx/4xx,
or an Alpine socket readiness response is not proof of full YouTube playback.
