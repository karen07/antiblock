#!/bin/sh
set -eu

ROOT=$(cd -- "$(dirname -- "$0")/../.." && pwd)
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT HUP INT TERM

for compiler in gcc clang; do
    printf '\n=== Domain regressions: %s (ASan + UBSan) ===\n' "$compiler"
    "$compiler" -std=gnu99 -Wall -Wextra -Wpedantic -Werror \
        -O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer \
        -I"$ROOT/include" -I"$ROOT/hashmap/include" \
        "$ROOT/tests/unit/test_domains.c" \
        "$ROOT/src/domains.c" \
        "$ROOT/hashmap/src/array_hashmap.c" \
        -lcurl -o "$TMP/test-domains"
    ASAN_OPTIONS=detect_leaks=1 UBSAN_OPTIONS=halt_on_error=1 \
        "$TMP/test-domains"

    "$compiler" -std=gnu99 -Wall -Wextra -Wpedantic -Werror \
        -O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer \
        -I"$ROOT/include" -I"$ROOT/hashmap/include" \
        "$ROOT/tests/unit/test_http_chunk.c" \
        "$ROOT/hashmap/src/array_hashmap.c" \
        -lcurl -o "$TMP/test-http-chunk"
    ASAN_OPTIONS=detect_leaks=1 UBSAN_OPTIONS=halt_on_error=1 \
        "$TMP/test-http-chunk"

    "$compiler" -std=gnu99 -Wall -Wextra -Wpedantic -Werror \
        -O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer \
        -I"$ROOT/include" -I"$ROOT/hashmap/include" \
        "$ROOT/tests/unit/test_zero_ttl.c" \
        "$ROOT/src/telemetry.c" \
        "$ROOT/hashmap/src/array_hashmap.c" \
        -o "$TMP/test-zero-ttl"
    ASAN_OPTIONS=detect_leaks=1 UBSAN_OPTIONS=halt_on_error=1 \
        "$TMP/test-zero-ttl"
    "$compiler" -std=gnu99 -Wall -Wextra -Wpedantic -Werror \
        -O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer \
        -I"$ROOT/include" -I"$ROOT/hashmap/include" \
        "$ROOT/tests/unit/test_capacity.c" \
        "$ROOT/src/domains.c" \
        "$ROOT/src/telemetry.c" \
        "$ROOT/hashmap/src/array_hashmap.c" \
        -lcurl -o "$TMP/test-capacity"
    ASAN_OPTIONS=detect_leaks=1 UBSAN_OPTIONS=halt_on_error=1 \
        "$TMP/test-capacity"
    "$compiler" -std=gnu99 -Wall -Wextra -Wpedantic -Werror \
        -O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer \
        -I"$ROOT/hashmap/include" \
        "$ROOT/tests/unit/test_hashmap.c" \
        "$ROOT/hashmap/src/array_hashmap.c" \
        -o "$TMP/test-hashmap"
    ASAN_OPTIONS=detect_leaks=1 UBSAN_OPTIONS=halt_on_error=1 \
        "$TMP/test-hashmap"

    "$compiler" -std=gnu99 -Wall -Wextra -Wpedantic -Werror \
        -O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer \
        -I"$ROOT/include" -I"$ROOT/hashmap/include" \
        "$ROOT/tests/unit/test_telemetry_log.c" \
        "$ROOT/src/telemetry.c" \
        -o "$TMP/test-telemetry-log"
    ASAN_OPTIONS=detect_leaks=1 UBSAN_OPTIONS=halt_on_error=1 \
        "$TMP/test-telemetry-log"

    "$compiler" -std=gnu99 -Wall -Wextra -Wpedantic -Werror \
        -O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer \
        -I"$ROOT/include" -I"$ROOT/hashmap/include" \
        "$ROOT/tests/unit/test_route_failures.c" \
        "$ROOT/src/telemetry.c" \
        "$ROOT/hashmap/src/array_hashmap.c" \
        -o "$TMP/test-route-failures"
    ASAN_OPTIONS=detect_leaks=1 UBSAN_OPTIONS=halt_on_error=1 \
        "$TMP/test-route-failures"
done
