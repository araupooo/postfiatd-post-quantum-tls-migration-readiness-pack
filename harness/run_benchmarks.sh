#!/bin/sh
# run_benchmarks.sh — build liboqs (if needed), compile the harnesses,
# run the KEM, classical, and hybrid benchmarks, and write the unedited
# output to $MEASUREMENT_OUTDIR (default outputs/).
# Single-threaded throughout. Total runtime a few minutes.
#
# liboqs source: LIBOQS_SRC, or ~/liboqs when it exists and its HEAD is
# the pinned 0.14.0 commit 94b421ebb82405c843dba4e9aa521a56ee5a333d,
# otherwise a fresh clone of tag 0.14.0 into .deps/liboqs (network).
# The build directory is LIBOQS_BUILD_DIR, default $LIBOQS_SRC/build.
set -eu
cd "$(dirname "$0")/.."
PACK_DIR="$(pwd)"
PINNED_LIBOQS_COMMIT="94b421ebb82405c843dba4e9aa521a56ee5a333d"
OUTDIR="${MEASUREMENT_OUTDIR:-outputs}"

if [ -n "${LIBOQS_SRC:-}" ]; then
    LIBOQS_SRC_DIR="$LIBOQS_SRC"
elif [ -d "$HOME/liboqs" ] && [ "$(git -C "$HOME/liboqs" rev-parse HEAD 2>/dev/null || echo none)" = "$PINNED_LIBOQS_COMMIT" ]; then
    LIBOQS_SRC_DIR="$HOME/liboqs"
else
    LIBOQS_SRC_DIR="$PACK_DIR/.deps/liboqs"
    if [ ! -d "$LIBOQS_SRC_DIR" ]; then
        echo "liboqs not found locally; cloning tag 0.14.0..."
        git clone --depth 1 --branch 0.14.0 https://github.com/open-quantum-safe/liboqs.git "$LIBOQS_SRC_DIR"
    fi
fi
LIBOQS_BUILD="${LIBOQS_BUILD_DIR:-$LIBOQS_SRC_DIR/build}"
# Reuse an already-built library for this exact source tree when the
# default build directory has none (e.g. a previous local build in
# /tmp/liboqs/build); this only skips the build, it never skips the
# commit check above, and CI (fresh clone) always builds from source.
if [ ! -f "$LIBOQS_BUILD/lib/liboqs.a" ] && [ "$LIBOQS_SRC_DIR" = "$HOME/liboqs" ] && [ -f /tmp/liboqs/build/lib/liboqs.a ]; then
    LIBOQS_BUILD="/tmp/liboqs/build"
fi
echo "step: liboqs source: $LIBOQS_SRC_DIR"
echo "step: liboqs commit: $(git -C "$LIBOQS_SRC_DIR" rev-parse HEAD)"
if [ "$(git -C "$LIBOQS_SRC_DIR" rev-parse HEAD)" != "$PINNED_LIBOQS_COMMIT" ]; then
    echo "ERROR: liboqs HEAD is not the pinned 0.14.0 commit $PINNED_LIBOQS_COMMIT"
    exit 1
fi
if [ ! -f "$LIBOQS_BUILD/lib/liboqs.a" ]; then
    echo "step: building liboqs (one-time, a few minutes)..."
    cmake -S "$LIBOQS_SRC_DIR" -B "$LIBOQS_BUILD" -DOQS_BUILD_ONLY_LIB=ON -DCMAKE_BUILD_TYPE=Release -DOQS_DIST_BUILD=OFF
    cmake --build "$LIBOQS_BUILD" -j 2
fi
echo "step: liboqs library: $LIBOQS_BUILD/lib/liboqs.a"

mkdir -p "$OUTDIR"
cc -O2 -I"$LIBOQS_SRC_DIR/src" -I"$LIBOQS_BUILD/include" \
    harness/bench_kem.c -L"$LIBOQS_BUILD/lib" -loqs -lcrypto -lm -o harness/bench_kem
cc -O2 -I"$LIBOQS_SRC_DIR/src" -I"$LIBOQS_BUILD/include" \
    harness/bench_hybrid.c -L"$LIBOQS_BUILD/lib" -loqs -lcrypto -lm -o harness/bench_hybrid
echo "step: harnesses compiled"

./harness/bench_kem 500 1000 > "$OUTDIR/benchmark-kem.log" 2>&1
echo "step: benchmark-kem.log written"
./harness/bench_hybrid 200 > "$OUTDIR/hybrid_bench.log" 2>&1
echo "step: hybrid_bench.log written"
sh harness/classical_speed.sh "$OUTDIR"
echo "step: benchmark-classical.log written"
sh harness/environment.sh "$OUTDIR" "$PINNED_LIBOQS_COMMIT"
echo "step: environment.txt written"
