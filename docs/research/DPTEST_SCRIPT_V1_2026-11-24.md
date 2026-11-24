# DPTest Script 1 (experimental 0.8.0)

## Usage

Paste a script in Zapret2 diagnostics, validate/preview its expanded plan, then run it. The app copies a redacted full or partial journal to the clipboard automatically. All presets use the same parser and runner as pasted scripts, so editing test matrices requires no new APK as long as the primitives are already installed.

Example:

    dptest 1
    name "YouTube API test"
    scenario youtubei.googleapis.com
    ips 2
    attempts 3
    timeout_ms 5000
    methods plain,tlsrec-split,fake-5
    protocols h1,h2
    train off
    report redacted+clipboard

## Grammar

First non-comment line must be dptest 1. Lines starting with # are comments.

- name TITLE: optional human title before the first scenario.
- scenario PUBLIC-DNS-HOST: start a new scenario; multiple allowed, max 8.
- ips 1..8: protected public IPv4 indices from fixed certificate-verified DoH.
- attempts 1..3: independent network connections.
- timeout_ms 1000..15000: per-probe deadline.
- methods comma-separated known native strategy names.
- protocols comma-separated named native protocol tests.
- stop never | first_verified: continue or terminate on real verified content.
- train off | verified METHOD: explicit guarded local neural update.
- report redacted+clipboard: only supported logging mode.

Limits: <=16 KiB text, <=96 expanded sockets per script, <=240 seconds summed worst-case socket deadlines. No code evaluation, loops, imports, raw IP/URL/port/keys, arbitrary HTTP requests, filesystem access, shell, downloaded code, or global socket operations. Changing network or losing DoH generation stops the run. Cancellation copies an accurately marked partial report.

## Protocols actually implemented

h1, h2, tls12, tls13; google-h1, google-h2, google-tls12, google-tls13 (same pinned API IP with a separately verified genuine www.google.com SNI/HTTP Host); quic1, quic2 (handshake only); h3-get, h3-browse (fixed anonymous YouTube API only, not login or video playback). TLS 1.2/1.3 are exact forced versions with certificate validation.

## Available protected test outbounds

TCP: plain, split-1, split, tlsrec-split, disorder, plus **fake-1 through fake-16** (actual protected TTL variants; 21 total TCP methods available to scripts). The legacy one-click and AUTO lists remain unchanged.
UDP: plain, fake-3, fake-5.

These names refer to the currently implemented DPpass Alpine/Xray protected experimental outbounds. A similar name in Zapret, Zapret2 or ByeDPI is NOT proof of packet-level equivalence.

Upstream techniques such as multisplit, multidisorder, fakedsplit, fakeddisorder, hostfakesplit, syntdata/syndata, seqovl, badseq, md5sig, tcp-md5, urgent/OOB, udp-fake, ipfrag, reverse-frag, tcp-timestamp, wssize, autottl, TLS fake mutations, rndsni, dupsid, custom nfqws2 Lua scripts are NOT implemented in this engine. The DSL rejects these rather than simulating them. Implementing their exact semantics requires new audited native adapters and, for packet-level NFQUEUE, root/appropriate OS-level interception. The Android unprivileged VpnService mode does not automatically supply those capabilities.

## Neural learning

train verified METHOD only compiles with a 3-attempt H1 scenario on exactly two pinned IP indices, both baseline plain and the specific non-plain candidate included. Native Go records script observations separately from site_apply AUTO evidence. Training is accepted only if all baseline independent content checks are 0/3 while all candidate content checks are 3/3 on every selected IP. A TLS-only handshake, 4xx API response, repeat overwrite, or incomplete probe can never teach. A success teaches a bounded positive 0.7 content label to the local contextual MLP; it does NOT invent downstream video traffic or switch production routing. If no model is installed, return neural_unavailable. Model storage continues through existing local model persistence.

## Presets

1. HTTPS 7 methods, full H1 scan.
2. CDN real JPEG and YouTube API.
3. API eight public IPv4 with H1/H2.
4. Same-IP original API vs Google SNI.
5. TLS 1.2 vs TLS 1.3 on same IP.
6. QUIC v1 and v2 handshake.
7. HTTP/3 GET and fixed anonymous YouTube browse POST.
8. Neural training eligibility from real 3/3 verified HTML evidence.

## Future native capability work

Zapret2 uses nfqws2 and LuaJIT-based desynchronization; Zapret nfqws has a different packet pipeline; byedpi uses a local proxy with its own OOB/disorder operations. Do not pass raw arbitrary nfqws/Lua options to user scripts or run downloaded binaries. Add each upstream operation as a typed, bounded adapter with tests, platform privilege checks, original TLS SNI/hostname verification and privacy review. Only after an adapter actually exists should the parser register the name as executable.

Current release is diagnostic, not evidence of working YouTube feed, auth or video. Physical Android MOBILE/Wi-Fi validation is still required before merging to main.
