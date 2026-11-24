#!/usr/bin/env bash
set -euo pipefail
base="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
src="$base/vendor/byedpi"
out="$(mktemp -d)"
trap 'rm -rf "$out"' EXIT
# Check the exact Git blob IDs, including whitespace and MIT notice.
test "$(git hash-object "$src/packets.c")" = "2c3f0e41a7054b4e6baa6f405f640ba42d847eff"
test "$(git hash-object "$src/packets.h")" = "16f002a7eb607ed3495ef51d4abc248e9b80668b"
test "$(git hash-object "$src/LICENSE")" = "342905d38be83e9d540deae14987896826a74858"
# Host-only prototype: compile without CLI, proxy, event loop or sockets.
cc="${CC:-cc}"
"$cc" -std=c99 -D_DEFAULT_SOURCE -D_GNU_SOURCE -O1 -g \
  -fsanitize=address,undefined -fno-omit-frame-pointer \
  -I"$src" -c "$src/packets.c" -o "$out/packets.o"
"$cc" -std=c99 -D_DEFAULT_SOURCE -D_GNU_SOURCE -O1 -g \
  -Wall -Wextra -Werror -fsanitize=address,undefined -fno-omit-frame-pointer \
  -I"$src" -I"$base" -c "$base/packet_inspect.c" -o "$out/packet_inspect.o"
"${AR:-ar}" rcs "$out/libdppass-byedpi-packets.a" "$out/packets.o" "$out/packet_inspect.o"
"$cc" -std=c99 -D_DEFAULT_SOURCE -D_GNU_SOURCE -O1 -g \
  -fsanitize=address,undefined -fno-omit-frame-pointer \
  -I"$src" "$base/tests/byedpi_packets_test.c" \
  "$out/libdppass-byedpi-packets.a" -o "$out/byedpi-packets-test"
ASAN_OPTIONS=detect_leaks=1 UBSAN_OPTIONS=halt_on_error=1 "$out/byedpi-packets-test"

"$cc" -std=c99 -D_DEFAULT_SOURCE -D_GNU_SOURCE -O1 -g \
  -Wall -Wextra -Werror -fsanitize=address,undefined -fno-omit-frame-pointer \
  -I"$src" -I"$base" "$base/tests/packet_inspect_test.c" \
  "$out/libdppass-byedpi-packets.a" -o "$out/packet-inspect-test"
ASAN_OPTIONS=detect_leaks=1 UBSAN_OPTIONS=halt_on_error=1 "$out/packet-inspect-test"
