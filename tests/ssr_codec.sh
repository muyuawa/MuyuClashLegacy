#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")/.."

build="$PWD/.build/ssr-resume"
ssl="${MLSTREAM_OPENSSL_PREFIX:-/opt/local/libexec/openssl3}"
senko="$PWD/.deps/senko/sources/senko/daemon/core"
peer_rev=fd723a92c488d202b407323f0512987346944136
peer_archive="$build/shadowsocksr.tar.gz"
peer_root="$build/shadowsocksr-$peer_rev"
sodium_archive="$build/libsodium-1.0.20.tar.gz"
sodium_library="$build/sodium/lib/libsodium.dylib"

mkdir -p "$build"
archive() {
    local path="$1" url="$2" hash="$3"
    if [[ ! -f "$path" ]]; then
        curl --fail --silent --show-error --location "$url" -o "$path.part"
        mv "$path.part" "$path"
    fi
    printf '%s  %s\n' "$hash" "$path" | shasum -a 256 -c -
}

archive "$peer_archive" "https://codeload.github.com/shadowsocksrr/shadowsocksr/tar.gz/$peer_rev" \
    932fa17657ff21221fe78872229c2bbc66cac07290125613bd638eafab3e758f
if [[ ! -d "$peer_root" ]]; then
    tar -xzf "$peer_archive" -C "$build"
fi

archive "$sodium_archive" "https://download.libsodium.org/libsodium/releases/libsodium-1.0.20.tar.gz" \
    ebb65ef6ca439333c2bb41a0c1990587288da07f6c7fd07cb3a18cc18d30ce19
if [[ ! -f "$sodium_library" ]]; then
    tar -xzf "$sodium_archive" -C "$build"
    if ! (
        cd "$build/libsodium-1.0.20"
        ./configure --enable-minimal --disable-static --prefix="$build/sodium"
        make -j4
        make install
    ) > "$build/libsodium-build.log" 2>&1; then
        tail -40 "$build/libsodium-build.log" >&2
        exit 1
    fi
fi

"${CC:-clang}" -std=c11 -Wall -Wextra -Werror -O2 \
    -Iprotocols -I"$senko" -I"$ssl/include" \
    tests/ssr_codec.c protocols/MLSSR.c "$ssl/lib/libcrypto.a" -lz \
    -o "$build/ssr_codec"
DYLD_LIBRARY_PATH="$ssl/lib${DYLD_LIBRARY_PATH:+:$DYLD_LIBRARY_PATH}" \
    PYTHONPATH="$peer_root" MLSSR_SODIUM_LIBRARY="$sodium_library" \
    "${MLSTREAM_TEST_PYTHON:-python3}" tests/ssr_codec.py "$build/ssr_codec"

if [[ $# -gt 0 ]]; then
    if [[ $# -ne 2 || "$1" != --stream-archive || ! -f "$2" ]]; then
        echo "usage: $0 [--stream-archive /path/to/libmlstream.a]" >&2
        exit 64
    fi
    for source in stream_xray datagram_xray; do
        "${CC:-clang}" -O2 -fobjc-arc -DMLSTREAM_HOST -Iprotocols \
            "tests/$source.m" "$2" "$ssl/lib/libssl.a" "$ssl/lib/libcrypto.a" \
            -lz -framework Foundation -o "$build/$source"
    done
    DYLD_LIBRARY_PATH="$ssl/lib${DYLD_LIBRARY_PATH:+:$DYLD_LIBRARY_PATH}" \
        PYTHONPATH="$peer_root" MLSSR_SODIUM_LIBRARY="$sodium_library" \
        "${MLSTREAM_TEST_PYTHON:-python3}" tests/ssr_stream.py "$build/stream_xray" "$build/datagram_xray"
fi
