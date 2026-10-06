#!/bin/sh
set -eu

IMAGE=${IMAGE:-antiblock-integration}
ROOT=$(
    unset CDPATH
    cd -- "$(dirname -- "$0")/../.." && pwd
)

cd "$ROOT"

if [ "${INTEGRATION_NO_CACHE:-0}" = "1" ]; then
    docker build \
        --pull \
        --no-cache \
        -f tests/integration/Dockerfile \
        -t "$IMAGE" \
        .
else
    docker build \
        -f tests/integration/Dockerfile \
        -t "$IMAGE" \
        .
fi

_status=0

run_suite() {
    _name="$1"
    _binary="$2"
    shift 2

    printf '\n========================================\n'
    printf 'INTEGRATION TESTS: %s\n' "$_name"
    printf '========================================\n\n'

    if docker run --rm \
        --cap-add NET_ADMIN \
        --cap-add NET_RAW \
        -e "ANTIBLOCK_BIN=$_binary" \
        "$@" \
        "$IMAGE"; then
        return 0
    fi

    _status=1
    printf '\nFAILED: %s\n' "$_name" >&2
    return 0
}

run_suite "GCC release" "/src/build-gcc/antiblock"
run_suite "Clang release" "/src/build-clang/antiblock"
run_suite \
    "Clang ASan + UBSan" \
    "/src/build-clang-sanitize/antiblock" \
    -e "ASAN_OPTIONS=detect_leaks=0:halt_on_error=1:abort_on_error=1" \
    -e "UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1"

if [ "$_status" -eq 0 ]; then
    printf '\n========================================\n'
    printf 'ALL COMPILER AND SANITIZER RUNS PASSED\n'
    printf '========================================\n'
else
    printf '\n========================================\n' >&2
    printf 'ONE OR MORE TEST RUNS FAILED\n' >&2
    printf '========================================\n' >&2
fi

exit "$_status"
