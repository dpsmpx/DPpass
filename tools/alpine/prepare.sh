#!/bin/sh
# Prepare the same pinned Alpine 3.24/Termux PRoot runtime as DP_IDE.
# NDK=<Android NDK> sh tools/alpine/prepare.sh <jni-output> <assets-output> <cache>
# An optional user-space tool, never a source of Android root privileges.
set -eu
HERE=$(cd "$(dirname "$0")" && pwd)
JNI=${1:?missing JNI output directory}
ASSETS=${2:?missing assets output directory}
CACHE=${3:?missing cache directory}
: "${NDK:?Android NDK path is required}"
mkdir -p "$JNI/arm64-v8a" "$ASSETS/alpine" "$CACHE"
JNI=$(cd "$JNI" && pwd)
ASSETS=$(cd "$ASSETS" && pwd)
CACHE=$(cd "$CACHE" && pwd)
BUILT="$CACHE/built-aarch64"
NDK="$NDK" sh "$HERE/build-proot.sh" aarch64 "$BUILT" "$CACHE/proot-cache"
cp "$BUILT/proot" "$JNI/arm64-v8a/libproot.so"
cp "$BUILT/loader" "$JNI/arm64-v8a/libproot-loader.so"
TC=$(ls -d "$NDK"/toolchains/llvm/prebuilt/* | head -n 1)
"$TC/bin/aarch64-linux-android26-clang" -shared -fPIC -std=c11 -Wall -Wextra -Werror \
  -Wl,-z,max-page-size=16384 -o "$JNI/arm64-v8a/libdppass-alpine.so" "$HERE/dppass_alpine_native.c"
ROOTFS_URL="https://dl-cdn.alpinelinux.org/alpine/v3.24/releases/aarch64/alpine-minirootfs-3.24.3-aarch64.tar.gz"
ROOTFS_SHA="4d3f80afaebd447c5591a63a73bde380a149fe8b2d85488cafabb2ff97551f50"
ROOTFS="$CACHE/alpine-minirootfs-3.24.3-aarch64.tar.gz"
if [ ! -f "$ROOTFS" ]; then
  curl --fail --location --retry 3 --silent --show-error "$ROOTFS_URL" -o "$ROOTFS.tmp"
  mv "$ROOTFS.tmp" "$ROOTFS"
fi
ACTUAL=$(sha256sum "$ROOTFS" | cut -d ' ' -f 1)
[ "$ACTUAL" = "$ROOTFS_SHA" ] || { rm -f "$ROOTFS"; echo "Alpine minirootfs SHA-256 mismatch: $ACTUAL" >&2; exit 1; }
cp "$ROOTFS" "$ASSETS/alpine/rootfs.tgz"
cp "$HERE/NOTICE.txt" "$ASSETS/alpine/NOTICE.txt"
cp "$HERE/GPL-2.0.txt" "$ASSETS/alpine/GPL-2.0.txt"
printf '%s\n' "$ROOTFS_SHA" > "$ASSETS/alpine/rootfs.sha256"
echo "Verified PRoot + Alpine minirootfs arm64; native PTY bridge built"
