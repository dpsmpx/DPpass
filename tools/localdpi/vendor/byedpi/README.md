# ByeDPI source module — isolated A4 prototype

Imported unchanged from [hufrea/byedpi](https://github.com/hufrea/byedpi/tree/7efde1b1296eaaa187b70e951894dde17527489c)
(0.17.3, MIT, Copyright (c) 2024 hufrea).

| File | Upstream Git blob SHA-1 |
|---|---|
| packets.c | `2c3f0e41a7054b4e6baa6f405f640ba42d847eff` |
| packets.h | `16f002a7eb607ed3495ef51d4abc248e9b80668b` |
| LICENSE | `342905d38be83e9d540deae14987896826a74858` |

The pinned `packets.c` and `packets.h` are self-contained with C standard
library/POSIX headers (Windows branch uses Winsock). The full upstream
LICENSE is included unmodified. No CLI, proxy event loop, executable
or dependency from upstream has been imported in this step.

Run from the repository: `bash tools/localdpi/check_byedpi_packets.sh`.
The script verifies original Git blob IDs, builds a static library and
runs read-only host fixtures with ASan/UBSan. No network access is used.
The temporary build outputs are removed afterwards.

**Not connected to the Android APK, AUTO, Go bridge or ROOT yet.**
The module is a candidate for the common native library, not an
announcement of new live support. Existing Go parsers remain the
production implementation. Before integration, review parser bounds,
mutable globals, thread safety, malformed input, sanitizers and fuzzing.
In particular, upstream HTTP parsing performs backward whitespace and
port scanning; empty/malformed Host values need a complete bounds audit.
The selected fixtures are not a comprehensive security or parity test.

The existing ByeDPI executable remains the RC6 reference until a
replacement passes comparative physical tests.

## DPpass inspection ABI v1

`tools/localdpi/packet_inspect.h` exposes a bounded, read-only protocol
recognition hint (not a validated parser). It calls only the upstream
`is_tls_chello` and `is_http` predicates, with explicit length checks.
It exports no payload, borrowed pointer or host name; has no network
IO; does not call parse_http, parse_tls, or mutation functions. Inputs
and outputs must be distinct valid objects. Maximum input 16 KiB.
Host fixtures use exact-sized allocations, malformed/truncated inputs,
8192 deterministic mixed cases, ASan/UBSan, and input immutability checks.
This is not exhaustive fuzzing or proof of safety of the upstream module.
