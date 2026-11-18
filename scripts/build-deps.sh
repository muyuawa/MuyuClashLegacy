#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")/.."
task_root="$PWD"
task_cmake="${CMAKE:-$(command -v cmake)}"
task_prefix="$task_root/.build/deps"
task_flags=(-DCMAKE_SYSTEM_NAME=Generic -DCMAKE_C_COMPILER="$task_root/scripts/cc-ios" -DCMAKE_TRY_COMPILE_TARGET_TYPE=STATIC_LIBRARY -DCMAKE_BUILD_TYPE=MinSizeRel -DCMAKE_C_FLAGS='-Oz -DNDEBUG -ffunction-sections -fdata-sections -DMBEDTLS_PLATFORM_MS_TIME_ALT' -DCMAKE_INSTALL_PREFIX="$task_prefix" -DCMAKE_INSTALL_LIBDIR=lib -DBUILD_SHARED_LIBS=OFF)
mkdir -p .build/logs
"$task_cmake" -S .deps/mbedtls -B .build/mbedtls "${task_flags[@]}" -DENABLE_PROGRAMS=OFF -DENABLE_TESTING=OFF > .build/logs/mbedtls-config.log 2>&1
"$task_cmake" --build .build/mbedtls --parallel 4 > .build/logs/mbedtls-build.log 2>&1
"$task_cmake" --install .build/mbedtls > .build/logs/mbedtls-install.log 2>&1
"$task_cmake" -S .deps/curl -B .build/curl "${task_flags[@]}" -DCMAKE_PREFIX_PATH="$task_prefix" -DCURL_USE_MBEDTLS=ON -DCURL_USE_OPENSSL=OFF -DCURL_USE_SECTRANSP=OFF -DCURL_USE_LIBPSL=OFF -DCURL_DISABLE_LDAP=ON -DCURL_DISABLE_LDAPS=ON -DHTTP_ONLY=ON -DBUILD_CURL_EXE=OFF -DBUILD_TESTING=OFF -DCURL_ZLIB=OFF -DCURL_BROTLI=OFF -DCURL_ZSTD=OFF -DCURL_USE_LIBSSH2=OFF -DUSE_LIBIDN2=OFF -DUSE_NGHTTP2=OFF -DENABLE_THREADED_RESOLVER=ON -DCURL_CA_BUNDLE=none -DCURL_CA_PATH=none > .build/logs/curl-config.log 2>&1
"$task_cmake" --build .build/curl --parallel 4 > .build/logs/curl-build.log 2>&1
"$task_cmake" --install .build/curl > .build/logs/curl-install.log 2>&1
echo 'Subscription TLS dependencies built for ARMv7 / iOS 6.0.'
