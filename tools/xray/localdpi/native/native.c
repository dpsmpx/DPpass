//go:build linux && cgo && localdpi_native

/* One canonical vendored source; no second copy. For changes to included
 * sources outside this Go package, use a fresh build cache or go test -a. */
#include "../../../localdpi/vendor/byedpi/packets.c"
#include "../../../localdpi/packet_inspect.c"
