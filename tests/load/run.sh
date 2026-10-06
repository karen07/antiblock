#!/bin/sh
set -eu

usage() {
    cat <<'USAGE'
Usage:
  ./tests/load/run.sh cloudflare-top-1000000.csv [all|performance|stress]

Environment overrides:
  IMAGE=antiblock-load
  LOAD_WORK_DIR=tests/load/.work
  PREP_SAMPLE=100000
  PREP_RPS=250
  PREP_SEED=701184
  UPSTREAM_DNS=1.1.1.1:53
  DNS_CLIENT_REF=main
  DNS_SERVER_REF=main
  LOAD_NO_CACHE=0

The upstream resolver is contacted only when cache-A.data must be prepared.
All performance and stress traffic after that is local Docker traffic.
USAGE
}

if [ "$#" -lt 1 ] || [ "$#" -gt 2 ]; then
    usage >&2
    exit 2
fi

DATASET=$1
MODE=${2:-all}

case "$MODE" in
    all | performance | stress) ;;
    *)
        usage >&2
        exit 2
        ;;
esac

if [ ! -f "$DATASET" ]; then
    printf 'Dataset not found: %s\n' "$DATASET" >&2
    exit 2
fi

ROOT=$(
    unset CDPATH
    cd -- "$(dirname -- "$0")/../.." && pwd
)

DATASET_DIR=$(
    unset CDPATH
    cd -- "$(dirname -- "$DATASET")" && pwd
)
DATASET_ABS="$DATASET_DIR/$(basename -- "$DATASET")"

IMAGE=${IMAGE:-antiblock-load}
WORK_DIR=${LOAD_WORK_DIR:-$ROOT/tests/load/.work}
PREP_SAMPLE=${PREP_SAMPLE:-100000}
PREP_RPS=${PREP_RPS:-250}
PREP_SEED=${PREP_SEED:-701184}
UPSTREAM_DNS=${UPSTREAM_DNS:-1.1.1.1:53}
DNS_CLIENT_REF=${DNS_CLIENT_REF:-main}
DNS_SERVER_REF=${DNS_SERVER_REF:-main}
NETWORK=${LOAD_NETWORK:-antiblock-load-net}
SERVER_NAME=${LOAD_SERVER_NAME:-antiblock-load-dns}
SERVER_IP=${LOAD_SERVER_IP:-172.29.0.53}
RUNNER_IP=${LOAD_RUNNER_IP:-172.29.0.2}
SUBNET=${LOAD_SUBNET:-172.29.0.0/24}

mkdir -p "$WORK_DIR"

cd "$ROOT"

printf '\n========================================\n'
printf 'BUILD LOAD TEST IMAGE\n'
printf '========================================\n\n'

if [ "${LOAD_NO_CACHE:-0}" = "1" ]; then
    docker build \
        --pull \
        --no-cache \
        --build-arg "DNS_CLIENT_REF=$DNS_CLIENT_REF" \
        --build-arg "DNS_SERVER_REF=$DNS_SERVER_REF" \
        -f tests/load/Dockerfile \
        -t "$IMAGE" \
        .
else
    docker build \
        --build-arg "DNS_CLIENT_REF=$DNS_CLIENT_REF" \
        --build-arg "DNS_SERVER_REF=$DNS_SERVER_REF" \
        -f tests/load/Dockerfile \
        -t "$IMAGE" \
        .
fi

DNS_CLIENT_COMMIT=$(docker run --rm "$IMAGE" git -C /opt/dns-client-test rev-parse HEAD)

printf '\n========================================\n'
printf 'PREPARE CLOUDFLARE DATASET\n'
printf '========================================\n\n'

docker run --rm \
    --user "$(id -u):$(id -g)" \
    -v "$DATASET_ABS:/input.csv:ro" \
    -v "$WORK_DIR:/work" \
    "$IMAGE" \
    python -u /src/tests/load/load_test.py prepare \
    /input.csv \
    /work/domains.txt

DATASET_SHA=$(sha256sum "$WORK_DIR/domains.txt" | awk '{print $1}')
CACHE_KEY="$DATASET_SHA $UPSTREAM_DNS $PREP_SAMPLE $PREP_SEED $DNS_CLIENT_COMMIT A"
CACHE_VALID=0

if [ -s "$WORK_DIR/cache-A.data" ] \
    && [ -s "$WORK_DIR/out_domains-A.txt" ] \
    && [ -f "$WORK_DIR/cache.input" ]; then
    OLD_KEY=$(cat "$WORK_DIR/cache.input")
    if [ "$OLD_KEY" = "$CACHE_KEY" ]; then
        CACHE_VALID=1
    fi
fi

if [ "$CACHE_VALID" -eq 0 ]; then
    printf '\nNo matching DNS replay cache found.\n'
    printf 'Preparing it once through %s at %s RPS.\n' "$UPSTREAM_DNS" "$PREP_RPS"
    printf 'dns-client-test samples %s domains with seed %s.\n\n' "$PREP_SAMPLE" "$PREP_SEED"

    rm -f \
        "$WORK_DIR/cache-A.data" \
        "$WORK_DIR/out_domains-A.txt" \
        "$WORK_DIR/ips-A.txt" \
        "$WORK_DIR/cache.input"

    if docker run --rm \
        --user "$(id -u):$(id -g)" \
        -v "$WORK_DIR:/work" \
        -w /work \
        "$IMAGE" \
        /opt/dns-client-test/build/release/dns-client-test \
        -f /work/domains.txt \
        -d "$UPSTREAM_DNS" \
        -r "$PREP_RPS" \
        -A \
        -n "$PREP_SAMPLE" \
        --seed "$PREP_SEED" \
        --save; then
        :
    else
        printf '\nDNS replay-cache preparation failed.\n' >&2
        printf 'Partial output is not marked as reusable.\n' >&2
        exit 1
    fi

    if [ ! -s "$WORK_DIR/cache-A.data" ] || [ ! -s "$WORK_DIR/out_domains-A.txt" ]; then
        printf 'dns-client-test did not create a usable cache-A.data/out_domains-A.txt pair.\n' >&2
        exit 1
    fi

    printf '%s\n' "$CACHE_KEY" >"$WORK_DIR/cache.input"
else
    printf 'Reusing existing replay cache for this dataset/sample.\n'
fi

printf 'Full AntiBlock domain table: %s domains\n' "$(wc -l <"$WORK_DIR/domains.txt")"
printf 'Replay cache domains       : %s domains\n' "$(wc -l <"$WORK_DIR/out_domains-A.txt")"

cleanup() {
    docker rm -f "$SERVER_NAME" >/dev/null 2>&1 || true
    docker network rm "$NETWORK" >/dev/null 2>&1 || true
}
trap cleanup EXIT HUP INT TERM

cleanup

docker network create --subnet "$SUBNET" "$NETWORK" >/dev/null

docker run -d --rm \
    --name "$SERVER_NAME" \
    --network "$NETWORK" \
    --ip "$SERVER_IP" \
    -v "$WORK_DIR:/work:ro" \
    -w /work \
    "$IMAGE" \
    /opt/dns-server-test/build/release/dns-server-test \
    -l 0.0.0.0:5300 \
    -c /work/cache-A.data >/dev/null

sleep 1
if ! docker ps --format '{{.Names}}' | grep -Fx "$SERVER_NAME" >/dev/null; then
    printf 'Local dns-server-test failed to start.\n' >&2
    docker logs "$SERVER_NAME" >&2 || true
    exit 1
fi

printf '\n========================================\n'
printf 'RUN LOAD / STRESS SUITE\n'
printf '========================================\n\n'

docker run --rm \
    --network "$NETWORK" \
    --ip "$RUNNER_IP" \
    --cap-add NET_ADMIN \
    --cap-add NET_RAW \
    -v "$WORK_DIR:/work:ro" \
    -e "DNS_SERVER=$SERVER_IP:5300" \
    -e "ASAN_OPTIONS=detect_leaks=0:halt_on_error=1:abort_on_error=1" \
    -e "UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1" \
    -e "LOAD_RATES=${LOAD_RATES:-10000 25000 50000 100000 200000 400000}" \
    -e "LOAD_REQUESTS=${LOAD_REQUESTS:-200000}" \
    -e "COLD_REQUESTS=${COLD_REQUESTS:-50000}" \
    -e "COLD_RPS=${COLD_RPS:-50000}" \
    -e "HOT_SET_SIZE=${HOT_SET_SIZE:-32}" \
    -e "ZERO_LOSS_PERCENT=${ZERO_LOSS_PERCENT:-99.5}" \
    -e "ROUTE_QUERY_COUNT=${ROUTE_QUERY_COUNT:-256}" \
    -e "ROUTE_CYCLES=${ROUTE_CYCLES:-5}" \
    -e "ROUTE_RPS=${ROUTE_RPS:-100000}" \
    -e "STRESS_REQUESTS=${STRESS_REQUESTS:-500000}" \
    -e "STRESS_RPS=${STRESS_RPS:-50000}" \
    -e "ROUTE_STRESS_QUERY_COUNT=${ROUTE_STRESS_QUERY_COUNT:-128}" \
    -e "ROUTE_STRESS_CYCLES=${ROUTE_STRESS_CYCLES:-10}" \
    -e "ROUTE_STRESS_RPS=${ROUTE_STRESS_RPS:-20000}" \
    "$IMAGE" \
    python -u /src/tests/load/load_test.py run "$MODE"
