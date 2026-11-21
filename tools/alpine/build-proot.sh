#!/bin/sh
# proot Linux-среды приложения (D-115): форк Termux (termux/proot) из закреплённого коммита,
# статически под musl — так же, как Alpine собирает proot-static, но код — форка Termux: вызов,
# запрещённый фильтром seccomp Android, он превращает в ответ ENOSYS, а не в смерть процесса
# сигналом SIGSYS (docs/research/LINUX_IN_APP.md, §10).
#
#   NDK=<каталог NDK> tools/linux/build-proot.sh aarch64|x86_64 <каталог итога> [<каталог загрузок>]
#   → <итог>/proot, <итог>/loader (загрузчик — отдельным файлом, путь — PROOT_LOADER)
#
# aarch64 — для APK (задача linuxFiles модуля android), x86_64 — для проверок на машине сборки
# (host-env.sh). Компилятор — clang из NDK; sysroot — пакеты Alpine 3.24 по закреплённым суммам
# (musl, заголовки ядра, talloc). Код proot не правится: только заголовок proot-musl-compat.h.
# Нужны sh, git, curl, tar; Linux или macOS.
set -eu

ARCH=${1:?aarch64 или x86_64}
OUT=${2:?каталог итога}
CACHE=${3:-${XDG_CACHE_HOME:-$HOME/.cache}/dpai-proot}
NDK=${NDK:?каталог NDK в переменной NDK}
HERE=$(cd "$(dirname "$0")" && pwd)

# Тег v5.1.107.102 — версия, которую выпускает пакет proot Termux (packages/proot/build.sh).
COMMIT=52d65a4dc140ca554d241a1438ddd4f6b00c9813
VERSION=v5.1.107.102
REPO=https://github.com/termux/proot
ALPINE=https://dl-cdn.alpinelinux.org/alpine/v3.24/main/$ARCH

# Пакет и сумма SHA-256 — закреплены 9 ноября 2026: загрузка `apk fetch` (подпись APKINDEX ключом
# Alpine этой архитектуры и сумма пакета в индексе проверены apk), docs/PROVENANCE.md, §4.
case $ARCH in
aarch64) PINS="
musl-dev-1.2.6-r3 45afe0a9f78de3402b6b5d11f5153ed955bf59d59b45344d9c3fed9f4bbf2f66
linux-headers-7.0.0-r1 d61656e81116040ebac0bc8d9046a3ba97f01a00ee085809103576e8a437468f
talloc-dev-2.4.4-r1 e1127751ace6a05ee40cde15e5001fc035a89feccf6a32338bb2d4642c182438
talloc-static-2.4.4-r1 c5b29fe708de96cbe045764d1bcabb3a934dc04fa4f5992ed2d479c39f794c38
bsd-compat-headers-0.7.2-r6 16b7f8b09b067649dfcfb25e366ffcf781fffb9a60e96fc14001f88035b10389" ;;
x86_64) PINS="
musl-dev-1.2.6-r3 310b51cff12e1d5ce5f135c558a82e2550427da5465bbd16c9ff9b05e63ee3d9
linux-headers-7.0.0-r1 c4535f3f0dc6fd4d80efa7ff2a7a72a2d3f8dae31e2587c0785cc3243889cdf2
talloc-dev-2.4.4-r1 d499f12946434f96802b8a9b155b589b4fb9535aae1d83f342eb29536d38459e
talloc-static-2.4.4-r1 12c35cb6f63d97f2bdd773cfd4290e39e6fbbd13026c485c6ab0497864927cd9
bsd-compat-headers-0.7.2-r6 185af20c670894721f8b5bc9be1294bd42cc698b4ab6b782880ff5cedbf98b98" ;;
*) echo "build-proot.sh: архитектура — aarch64 или x86_64, а не $ARCH" >&2; exit 2 ;;
esac

fail() { echo "build-proot.sh: $*" >&2; exit 1; }
sha256() { if command -v sha256sum >/dev/null; then sha256sum "$1"; else shasum -a 256 "$1"; fi | cut -d ' ' -f 1; }

TC=$(ls -d "$NDK"/toolchains/llvm/prebuilt/*/ 2>/dev/null | head -n 1)
[ -n "$TC" ] && [ -x "$TC/bin/clang" ] || fail "нет clang в $NDK/toolchains/llvm/prebuilt"
BUILTINS=$(ls "$TC"/lib/clang/*/lib/linux/libclang_rt.builtins-"$ARCH"-android.a 2>/dev/null | head -n 1)
[ -n "$BUILTINS" ] || fail "нет libclang_rt.builtins-$ARCH-android.a в NDK"

mkdir -p "$CACHE" "$OUT"
CACHE=$(cd "$CACHE" && pwd)
OUT=$(cd "$OUT" && pwd)

# Исходники — git по коммиту: адрес архива GitHub отдаёт не каждый прокси, а коммит и так
# закрепляет всё дерево. Каталог уже есть, но не тот коммит или правленый, — отказ, не стирание.
SRC=$CACHE/proot-$COMMIT
if [ ! -d "$SRC" ]; then
    TMP=$(mktemp -d "$CACHE/proot-fetch.XXXXXX")
    git -C "$TMP" init -q
    git -C "$TMP" fetch -q --depth 1 "$REPO" "$COMMIT"
    git -C "$TMP" -c advice.detachedHead=false checkout -q FETCH_HEAD
    mv "$TMP" "$SRC"
fi
[ "$(git -C "$SRC" rev-parse HEAD)" = "$COMMIT" ] || fail "$SRC — не коммит $COMMIT; удалите каталог"
git -C "$SRC" diff --quiet HEAD && [ -z "$(git -C "$SRC" status --porcelain)" ] || fail "$SRC изменён; удалите каталог"

# sysroot: пакеты Alpine по суммам, распакованные в свой каталог (имя — от набора сумм).
SYSROOT=$CACHE/sysroot-$ARCH-$(printf '%s' "$PINS" | cksum | cut -d ' ' -f 1)
if [ ! -f "$SYSROOT/.ready" ]; then
    mkdir -p "$SYSROOT"
    echo "$PINS" | while read -r name sum; do
        [ -n "$name" ] || continue
        file=$CACHE/$ARCH-$name.apk
        if [ ! -f "$file" ]; then curl -sS -fL -o "$file.part" "$ALPINE/$name.apk" && mv "$file.part" "$file"; fi
        [ "$(sha256 "$file")" = "$sum" ] || { rm -f "$file"; fail "$name.apk: сумма не та"; }
        # Пакет apk — потоки gzip подряд; у tar — предупреждения о ключах APK-TOOLS, они не ошибки.
        tar -xzf "$file" -C "$SYSROOT" 2>/dev/null || true
    done
    for f in usr/lib/rcrt1.o usr/lib/libc.a usr/lib/libtalloc.a usr/include/talloc.h usr/include/sys/queue.h usr/include/linux/seccomp.h; do
        [ -f "$SYSROOT/$f" ] || fail "в sysroot нет $f"
    done
    touch "$SYSROOT/.ready"
fi

CC="$TC/bin/clang --target=$ARCH-linux-musl --sysroot=$SYSROOT"
B=$(mktemp -d "$OUT/build.XXXXXX")
S=$SRC/src
arch_value() { $CC -E -dM -DNO_LIBC_HEADER "$S/arch.h" | awk -v k="$1" '$2 == k { $1 = ""; $2 = ""; sub(/^ +/, ""); print }'; }
LOADER_ADDRESS=$(arch_value LOADER_ADDRESS)
LOADER_ARCH_CFLAGS=$(arch_value LOADER_ARCH_CFLAGS)
POKEDATA=$(arch_value HAS_POKEDATA_WORKAROUND)
[ -n "$LOADER_ADDRESS" ] || fail "в arch.h нет LOADER_ADDRESS для $ARCH"

# build.h — то, что GNUmakefile форка выясняет пробной сборкой: у Linux с musl есть оба.
cat > "$B/build.h" <<EOF
#ifndef BUILD_H
#define BUILD_H
#undef VERSION
#define VERSION "$VERSION-musl"
#define HAVE_PROCESS_VM
#define HAVE_SECCOMP_FILTER
#endif
EOF

# Загрузчик — отдельным файлом (PROOT_UNBUNDLE_LOADER): его путь даёт PROOT_LOADER (ProotHost).
# Пути каталогов — без машины сборки (строки __FILE__ в assert): итог не зависит от того, где собирали.
CPPFLAGS="-D_FILE_OFFSET_BITS=64 -D_GNU_SOURCE -D_LARGEFILE64_SOURCE -I$B -I$S -include $HERE/proot-musl-compat.h"
CPPFLAGS="$CPPFLAGS -ffile-prefix-map=$S/=proot/ -ffile-prefix-map=$B/=build/ -ffile-prefix-map=$HERE/=tools/linux/"
compile() { # исходник объект флаги…
    src=$1; obj=$2; shift 2
    mkdir -p "$(dirname "$obj")"
    # shellcheck disable=SC2086 # флаги — словами
    $CC $CPPFLAGS -O2 -w "$@" -c "$src" -o "$obj"
}
LOADER_CFLAGS="-fPIC -ffreestanding -fno-stack-protector $LOADER_ARCH_CFLAGS"
# shellcheck disable=SC2086
compile "$S/loader/loader.c" "$B/loader/loader.o" $LOADER_CFLAGS
# shellcheck disable=SC2086
compile "$S/loader/assembly.S" "$B/loader/assembly.o" $LOADER_CFLAGS
$CC -static -nostdlib -fuse-ld=lld "-Wl,--build-id=none,-Ttext=$LOADER_ADDRESS,--rosegment,-z,noexecstack" \
    -o "$B/loader/loader" "$B/loader/loader.o" "$B/loader/assembly.o"

# Объекты proot — по списку OBJECTS из GNUmakefile форка, без встроенного загрузчика.
OBJECTS=$(sed -n '/^OBJECTS += /,/^$/p' "$S/GNUmakefile" | tr -d '\\' | tr -s ' \t' '\n' | grep '\.o$')
if [ -n "$POKEDATA" ]; then
    # loader-info.c — как loader/loader-info.awk: смещение pokedata_workaround от _start загрузчика.
    nm_addr() { "$TC/bin/llvm-nm" "$B/loader/loader" | awk -v k="$1" '$3 == k { print $1 }'; }
    P=$(nm_addr pokedata_workaround)
    T=$(nm_addr _start)
    [ -n "$P" ] && [ -n "$T" ] || fail "в загрузчике нет pokedata_workaround или _start"
    printf '#include <unistd.h>\nconst ssize_t offset_to_pokedata_workaround=%s;\n' "$((0x$P - 0x$T))" > "$B/loader-info.c"
    compile "$B/loader-info.c" "$B/loader/loader-info.o" -fPIE
fi
LINK=
for o in $OBJECTS; do
    compile "$S/${o%.o}.c" "$B/$o" -fPIE '-DPROOT_UNBUNDLE_LOADER="/proot-loader-is-PROOT_LOADER"'
    LINK="$LINK $B/$o"
done
[ -z "$POKEDATA" ] || LINK="$LINK $B/loader/loader-info.o"

L=$SYSROOT/usr/lib
# shellcheck disable=SC2086 # список объектов — словами
$CC -static-pie -nostdlib -fuse-ld=lld -Wl,-z,noexecstack -o "$B/proot" \
    "$L/rcrt1.o" "$L/crti.o" $LINK "-L$L" -ltalloc -lc "$BUILTINS" "$L/crtn.o"

"$TC/bin/llvm-strip" --strip-all -o "$OUT/proot" "$B/proot"
"$TC/bin/llvm-strip" --strip-all -o "$OUT/loader" "$B/loader/loader"
chmod 755 "$OUT/proot" "$OUT/loader"
rm -rf "$B"
echo "proot $VERSION ($COMMIT), $ARCH: $OUT/proot, $OUT/loader"
