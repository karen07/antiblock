#!/usr/bin/env python3

import csv
import hashlib
import os
import random
import re
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path

DNS_CLIENT_BIN = os.environ.get(
    "DNS_CLIENT_BIN", "/opt/dns-client-test/build/release/dns-client-test"
)
ANTIBLOCK_RELEASE_BIN = os.environ.get(
    "ANTIBLOCK_RELEASE_BIN", "/src/build-load-gcc/antiblock"
)
ANTIBLOCK_SANITIZE_BIN = os.environ.get(
    "ANTIBLOCK_SANITIZE_BIN", "/src/build-load-sanitize/antiblock"
)
DNS_SERVER = os.environ.get("DNS_SERVER", "172.29.0.53:5300")
WORK_DIR = Path("/work")

STAT_PROCESSED_RE = re.compile(r"DNS packets processed:\s*(\d+)")
STAT_ERRORS_RE = re.compile(r"DNS parsing errors\s*:\s*(\d+)")
STAT_ROUTE_RE = re.compile(r"Route\s+1\s+\([^)]*\):\s*(\d+)")
STAT_PCAP_RECEIVED_RE = re.compile(r"PCAP packets received\s*:\s*(\d+)")
STAT_PCAP_DROPPED_RE = re.compile(r"PCAP packets dropped\s*:\s*(\d+)")
STAT_PCAP_IF_DROPPED_RE = re.compile(r"PCAP interface dropped\s*:\s*(\d+)")
CLIENT_ROW_RE = re.compile(
    r"^\s*(\d+);\s*(\d+);\s*(\d+);\s*(\d+);\s*(\d+);\s*$",
    re.MULTILINE,
)
SANITIZER_MARKERS = (
    "ERROR: AddressSanitizer",
    "AddressSanitizer:DEADLYSIGNAL",
    "runtime error:",
    "UndefinedBehaviorSanitizer",
)


def env_int(name, default, minimum=1):
    raw = os.environ.get(name, str(default))
    try:
        value = int(raw)
    except ValueError as exc:
        raise RuntimeError(f"{name} must be an integer, got {raw!r}") from exc
    if value < minimum:
        raise RuntimeError(f"{name} must be >= {minimum}, got {value}")
    return value


def env_float(name, default, minimum=0.0, maximum=None):
    raw = os.environ.get(name, str(default))
    try:
        value = float(raw)
    except ValueError as exc:
        raise RuntimeError(f"{name} must be a number, got {raw!r}") from exc
    if value < minimum or (maximum is not None and value > maximum):
        raise RuntimeError(f"{name} is outside the allowed range: {value}")
    return value


def normalize_domain(value):
    value = value.strip().strip(".").lower()
    if not value or any(ch.isspace() for ch in value):
        return None
    try:
        value = value.encode("idna").decode("ascii")
    except UnicodeError:
        return None
    if len(value) > 253:
        return None
    labels = value.split(".")
    if any(not label or len(label) > 63 for label in labels):
        return None
    return value


def prepare_dataset(csv_path, domains_path):
    source = Path(csv_path)
    domains_out = Path(domains_path)

    domains = []
    seen = set()
    domain_column = None

    with source.open("r", encoding="utf-8-sig", newline="") as fp:
        reader = csv.reader(fp)
        for row_number, row in enumerate(reader, 1):
            if not row:
                continue
            if row_number == 1:
                lowered = [cell.strip().lower() for cell in row]
                if "domain" in lowered:
                    domain_column = lowered.index("domain")
                    continue
                domain_column = 0
            if domain_column is None or domain_column >= len(row):
                continue
            domain = normalize_domain(row[domain_column])
            if domain is None or domain in seen:
                continue
            seen.add(domain)
            domains.append(domain)

    if len(domains) < 1000:
        raise RuntimeError(
            f"only {len(domains)} usable domains were found; "
            "this does not look like a Top domains dataset"
        )

    domains_out.parent.mkdir(parents=True, exist_ok=True)
    domains_out.write_text(
        "".join(f"{domain}\n" for domain in domains), encoding="ascii"
    )

    digest = hashlib.sha256(domains_out.read_bytes()).hexdigest()
    print(f"Normalized domains : {len(domains):,}")
    print(f"Dataset SHA256     : {digest}")


def read_domains(path):
    result = []
    seen = set()
    with Path(path).open("r", encoding="ascii", errors="strict") as fp:
        for line in fp:
            domain = line.strip()
            if not domain or domain in seen:
                continue
            seen.add(domain)
            result.append(domain)
    return result


def write_lines(path, values):
    Path(path).write_text("".join(f"{value}\n" for value in values), encoding="ascii")


def repeated_workload(domains, total, seed):
    if not domains:
        raise RuntimeError("cannot build workload from an empty domain list")
    rng = random.Random(seed)
    result = []
    while len(result) < total:
        block = list(domains)
        rng.shuffle(block)
        need = total - len(result)
        result.extend(block[:need])
    return result


def banner(text):
    print("\n========================================")
    print(text)
    print("========================================\n")


def parse_stat(path):
    text = Path(path).read_text(encoding="utf-8", errors="replace")
    processed_match = STAT_PROCESSED_RE.search(text)
    errors_match = STAT_ERRORS_RE.search(text)
    route_match = STAT_ROUTE_RE.search(text)
    pcap_received_match = STAT_PCAP_RECEIVED_RE.search(text)
    pcap_dropped_match = STAT_PCAP_DROPPED_RE.search(text)
    pcap_if_dropped_match = STAT_PCAP_IF_DROPPED_RE.search(text)
    if processed_match is None or errors_match is None:
        raise RuntimeError(f"incomplete AntiBlock stat file: {path}")
    return {
        "processed": int(processed_match.group(1)),
        "parse_errors": int(errors_match.group(1)),
        "routes": int(route_match.group(1)) if route_match else 0,
        "pcap_received": (
            int(pcap_received_match.group(1)) if pcap_received_match else None
        ),
        "pcap_dropped": (
            int(pcap_dropped_match.group(1)) if pcap_dropped_match else None
        ),
        "pcap_if_dropped": (
            int(pcap_if_dropped_match.group(1)) if pcap_if_dropped_match else None
        ),
    }


def read_cpu_seconds(pid):
    try:
        fields = Path(f"/proc/{pid}/stat").read_text(encoding="ascii").split()
        ticks = os.sysconf(os.sysconf_names["SC_CLK_TCK"])
        return (int(fields[13]) + int(fields[14])) / ticks
    except (FileNotFoundError, ProcessLookupError):
        return None


def read_peak_rss_kib(pid):
    try:
        for line in (
            Path(f"/proc/{pid}/status").read_text(encoding="ascii").splitlines()
        ):
            if line.startswith("VmHWM:"):
                return int(line.split()[1])
    except (FileNotFoundError, ProcessLookupError):
        pass
    return 0


def route_count():
    count = 0
    text = Path("/proc/net/route").read_text(encoding="ascii", errors="strict")
    for line in text.splitlines()[1:]:
        fields = line.split()
        if len(fields) < 8:
            continue
        try:
            metric = int(fields[6], 10)
        except ValueError:
            continue
        if metric == 23117:
            count += 1
    return count


def wait_routes_stable(timeout=3.0, interval=0.025, stable_needed=4):
    deadline = time.monotonic() + timeout
    previous = -1
    stable = 0
    current = 0
    while time.monotonic() < deadline:
        current = route_count()
        if current == previous:
            stable += 1
            if stable >= stable_needed:
                return current
        else:
            stable = 0
            previous = current
        time.sleep(interval)
    return current


def sanitizer_clean(log_path):
    text = Path(log_path).read_text(encoding="utf-8", errors="replace")
    return not any(marker in text for marker in SANITIZER_MARKERS)


def client_command(workload, rps):
    return [
        DNS_CLIENT_BIN,
        "-f",
        str(workload),
        "-d",
        DNS_SERVER,
        "-r",
        str(rps),
        "-A",
    ]


def parse_client_output(output, elapsed):
    peak_send = 0
    peak_read = 0
    sent = 0
    read = 0
    for match in CLIENT_ROW_RE.finditer(output):
        send_rps, read_rps, sent_total, read_total, _diff = map(int, match.groups())
        peak_send = max(peak_send, send_rps)
        peak_read = max(peak_read, read_rps)
        sent = max(sent, sent_total)
        read = max(read, read_total)
    return {
        "elapsed": elapsed,
        "peak_send_qps": peak_send,
        "peak_read_qps": peak_read,
        "sent": sent,
        "read": read,
    }


def run_client(workload, rps):
    started = time.monotonic()
    result = subprocess.run(
        client_command(workload, rps),
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    elapsed = time.monotonic() - started
    print(result.stdout, end="", flush=True)
    if result.returncode != 0:
        raise RuntimeError(f"dns-client-test exited with {result.returncode}")
    return parse_client_output(result.stdout, elapsed)


def run_client_measure_route_peak(workload, rps, timeout=15.0, settle_seconds=0.75):
    started = time.monotonic()
    proc = subprocess.Popen(
        client_command(workload, rps),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )

    peak_routes = route_count()
    peak_at = started if peak_routes > 0 else None
    deadline = started + timeout

    while proc.poll() is None:
        now = time.monotonic()
        if now >= deadline:
            proc.kill()
            output, _unused = proc.communicate(timeout=5)
            print(output, end="", flush=True)
            raise RuntimeError("dns-client-test timed out during route programming")

        current = route_count()
        if current > peak_routes:
            peak_routes = current
            peak_at = now
        time.sleep(0.005)

    output, _unused = proc.communicate(timeout=5)
    elapsed = time.monotonic() - started
    print(output, end="", flush=True)
    if proc.returncode != 0:
        raise RuntimeError(f"dns-client-test exited with {proc.returncode}")

    # dns-client-test intentionally has a post-send receive tail. Do not include
    # that tail in route throughput. After the client exits, only wait long
    # enough to catch responses already buffered in libpcap/AntiBlock. Extend
    # the settle window whenever a new peak is observed.
    settle_deadline = time.monotonic() + settle_seconds
    while time.monotonic() < settle_deadline:
        current = route_count()
        now = time.monotonic()
        if current > peak_routes:
            peak_routes = current
            peak_at = now
            settle_deadline = now + settle_seconds
        time.sleep(0.005)

    if peak_routes <= 0 or peak_at is None:
        raise RuntimeError("no real AntiBlock routes were installed")

    route_elapsed = max(peak_at - started, 0.000001)
    return parse_client_output(output, elapsed), peak_routes, route_elapsed


class AntiBlockProcess:
    def __init__(self, binary, domains, test_mode, blacklist=None, sanitizer=False):
        self.tmp = tempfile.TemporaryDirectory(prefix="antiblock-load-")
        self.dir = Path(self.tmp.name)
        self.stat = self.dir / "stat.txt"
        self.log = self.dir / "antiblock.log"
        self.log_fp = self.log.open("w", encoding="utf-8")
        command = [
            binary,
            "-l",
            DNS_SERVER,
            "-r",
            f"lo {domains}",
            "-o",
            str(self.dir),
            "--stat",
        ]
        if test_mode:
            command.append("--test")
        if blacklist is not None:
            command.extend(["-b", str(blacklist)])

        env = os.environ.copy()
        if sanitizer:
            env.setdefault(
                "ASAN_OPTIONS", "detect_leaks=0:halt_on_error=1:abort_on_error=1"
            )
            env.setdefault("UBSAN_OPTIONS", "halt_on_error=1:print_stacktrace=1")

        self.proc = subprocess.Popen(
            command,
            stdout=self.log_fp,
            stderr=subprocess.STDOUT,
            env=env,
        )
        self.wait_ready()

    def wait_ready(self, timeout=60.0):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            rc = self.proc.poll()
            if rc is not None:
                self.log_fp.flush()
                log_text = self.log.read_text(errors="replace")
                raise RuntimeError(
                    f"AntiBlock exited during startup with {rc}:\n{log_text}"
                )
            if self.stat.exists():
                text = self.stat.read_text(encoding="utf-8", errors="replace")
                if "DNS packets processed:" in text:
                    return
            time.sleep(0.05)
        raise RuntimeError("AntiBlock did not become ready within 60 seconds")

    def stop(self):
        if self.proc.poll() is None:
            self.proc.send_signal(signal.SIGTERM)
            try:
                self.proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait(timeout=5)
        self.log_fp.flush()
        self.log_fp.close()
        return self.proc.returncode

    def stats(self):
        return parse_stat(self.stat)

    def log_text(self):
        if not self.log_fp.closed:
            self.log_fp.flush()
        return self.log.read_text(encoding="utf-8", errors="replace")

    def close(self):
        if self.proc.poll() is None:
            self.stop()
        elif not self.log_fp.closed:
            self.log_fp.close()
        self.tmp.cleanup()


def run_one_antiblock(
    binary,
    domains,
    workload,
    rps,
    test_mode,
    blacklist=None,
    sanitizer=False,
    route_stable=False,
    measure_route_time=False,
):
    ab = AntiBlockProcess(binary, domains, test_mode, blacklist, sanitizer)
    try:
        cpu_start = read_cpu_seconds(ab.proc.pid)
        started = time.monotonic()
        route_elapsed = None

        if measure_route_time:
            client, routes, route_elapsed = run_client_measure_route_peak(workload, rps)
        else:
            client = run_client(workload, rps)
            if route_stable:
                routes = wait_routes_stable()
            else:
                time.sleep(0.25)
                routes = route_count() if not test_mode else 0

        elapsed = time.monotonic() - started
        cpu_end = read_cpu_seconds(ab.proc.pid)
        peak_rss = read_peak_rss_kib(ab.proc.pid)

        if ab.proc.poll() is not None:
            raise RuntimeError(
                f"AntiBlock died under load with exit code {ab.proc.returncode}"
            )

        rc = ab.stop()
        stats = ab.stats()
        log_text = ab.log_text()
        if rc != 0:
            raise RuntimeError(f"AntiBlock exited with {rc}\n{log_text}")
        if sanitizer and not sanitizer_clean(ab.log):
            raise RuntimeError(f"sanitizer reported an error\n{log_text}")
        if stats["parse_errors"] != 0:
            raise RuntimeError(
                f"AntiBlock reported {stats['parse_errors']} DNS parse errors"
            )
        if "Route hashmap is full" in log_text:
            raise RuntimeError(
                "route hashmap filled during the workload; "
                "reduce HOT_SET_SIZE/ROUTE_QUERY_COUNT"
            )

        cpu_seconds = 0.0
        if cpu_start is not None and cpu_end is not None:
            cpu_seconds = max(0.0, cpu_end - cpu_start)

        return {
            "processed": stats["processed"],
            "routes_stat": stats["routes"],
            "routes_kernel": routes,
            "client_elapsed": client["elapsed"],
            "client_peak_send_qps": client["peak_send_qps"],
            "client_peak_read_qps": client["peak_read_qps"],
            "client_sent": client["sent"],
            "client_read": client["read"],
            "elapsed": elapsed,
            "route_elapsed": route_elapsed,
            "cpu_seconds": cpu_seconds,
            "peak_rss_kib": peak_rss,
            "pcap_received": stats["pcap_received"],
            "pcap_dropped": stats["pcap_dropped"],
            "pcap_if_dropped": stats["pcap_if_dropped"],
        }
    finally:
        ab.close()


def test_release_dns_throughput(full_domains, cached_domains, tmpdir):
    banner("TEST 1: RELEASE DNS THROUGHPUT")

    cold_requests = min(env_int("COLD_REQUESTS", 50000), len(cached_domains))
    cold_rps = env_int("COLD_RPS", 50000)
    cold_workload = tmpdir / "cold-workload.txt"
    write_lines(cold_workload, cached_domains[:cold_requests])

    blacklist = tmpdir / "blacklist-all.txt"
    blacklist.write_text("0.0.0.0/1\n128.0.0.0/1\n", encoding="ascii")

    cold = run_one_antiblock(
        ANTIBLOCK_RELEASE_BIN,
        full_domains,
        cold_workload,
        cold_rps,
        test_mode=True,
        blacklist=blacklist,
    )
    cold_received = cold["client_read"]
    if cold_received <= 0:
        raise RuntimeError("cold lookup sweep received no DNS responses")
    cold_ratio = 100.0 * cold["processed"] / cold_received

    print("Cold 1M-table lookup sweep (routes deliberately blacklisted):")
    print(f"  requests             : {cold_requests:,}")
    print(f"  configured rate      : {cold_rps:,} qps")
    print(f"  local response peak  : {cold['client_peak_read_qps']:,} qps")
    print(f"  client responses     : {cold_received:,}")
    print(f"  processed            : {cold['processed']:,} ({cold_ratio:.2f}%)")
    print(f"  pcap received        : {cold['pcap_received']}")
    print(f"  pcap dropped         : {cold['pcap_dropped']}")
    print(f"  pcap interface drop  : {cold['pcap_if_dropped']}")
    print(f"  AntiBlock CPU time   : {cold['cpu_seconds']:.3f} s")
    print(f"  AntiBlock peak RSS   : {cold['peak_rss_kib'] / 1024.0:.1f} MiB")

    hot_set_size = min(env_int("HOT_SET_SIZE", 32), len(cached_domains))
    hot_set = cached_domains[:hot_set_size]
    load_requests = env_int("LOAD_REQUESTS", 200000)
    hot_workload = tmpdir / "hot-workload.txt"
    write_lines(hot_workload, repeated_workload(hot_set, load_requests, 0xA17B10C))

    rates = []
    for token in os.environ.get(
        "LOAD_RATES", "10000 25000 50000 100000 200000 400000"
    ).split():
        value = int(token)
        if value <= 0:
            raise RuntimeError(f"invalid LOAD_RATES value: {value}")
        rates.append(value)
    if not rates:
        raise RuntimeError("LOAD_RATES is empty")

    zero_loss = env_float("ZERO_LOSS_PERCENT", 99.5, 0.0, 100.0)
    best_observed = None
    last_result = None
    print("\nHot-set full userspace path (--test, route-state lookup/update enabled):")
    print(
        "  cfg-qps   local-peak   processed   capture%   pcap-drop   "
        "CPU(s)   peak-RSS"
    )
    for rate in rates:
        result = run_one_antiblock(
            ANTIBLOCK_RELEASE_BIN,
            full_domains,
            hot_workload,
            rate,
            test_mode=True,
        )
        responses = result["client_read"]
        if responses <= 0:
            raise RuntimeError(f"load step {rate} qps received no DNS responses")
        ratio = 100.0 * result["processed"] / responses
        pcap_drop = result["pcap_dropped"]
        pcap_drop_text = "?" if pcap_drop is None else f"{pcap_drop:,}"
        observed = result["client_peak_read_qps"]
        print(
            f"  {rate:7,d}   {observed:10,d}   {result['processed']:9,d}   "
            f"{ratio:8.2f}   {pcap_drop_text:>9}   "
            f"{result['cpu_seconds']:6.3f}   "
            f"{result['peak_rss_kib'] / 1024.0:7.1f} MiB"
        )
        if ratio >= zero_loss and (pcap_drop is None or pcap_drop == 0):
            best_observed = max(best_observed or 0, observed)
        last_result = result

    if best_observed is None:
        print(f"\n  no step met the >= {zero_loss:.2f}% capture target")
    else:
        print(
            f"\n  sustainable observed local response rate: "
            f">= {best_observed:,} qps"
        )

    if last_result is not None:
        last_observed = last_result["client_peak_read_qps"]
        if last_observed < rates[-1] * 0.90:
            print(
                "  note: the C load source/replay path did not reach the highest "
                "configured rate"
            )
            print(
                f"        configured {rates[-1]:,} qps, observed peak "
                f"{last_observed:,} qps"
            )
            if best_observed is not None:
                print("        AntiBlock throughput is therefore a lower bound")

    print("[PASS] release DNS throughput benchmark completed")


def test_release_route_programming(cached_domains, tmpdir):
    banner("TEST 2: RELEASE REAL KERNEL ROUTE PROGRAMMING")

    count = min(env_int("ROUTE_QUERY_COUNT", 256), len(cached_domains))
    cycles = env_int("ROUTE_CYCLES", 5)
    rps = env_int("ROUTE_RPS", 100000)
    route_domains = tmpdir / "route-domains.txt"
    route_workload = tmpdir / "route-workload.txt"
    write_lines(route_domains, cached_domains[:count])
    write_lines(route_workload, cached_domains[:count])

    rates = []
    for cycle in range(1, cycles + 1):
        result = run_one_antiblock(
            ANTIBLOCK_RELEASE_BIN,
            route_domains,
            route_workload,
            rps,
            test_mode=False,
            measure_route_time=True,
        )
        routes = result["routes_kernel"]
        route_elapsed = result["route_elapsed"]
        if routes <= 0 or route_elapsed is None:
            raise RuntimeError("no real AntiBlock routes were installed")
        rate = routes / route_elapsed
        rates.append(rate)
        if route_count() != 0:
            raise RuntimeError("AntiBlock-owned routes remained after SIGTERM cleanup")
        print(
            f"  cycle {cycle:2d}: routes={routes:4d}, "
            f"route-time={route_elapsed:.6f}s, {rate:,.0f} routes/s"
        )

    ordered = sorted(rates)
    median = ordered[len(ordered) // 2]
    print(f"\n  median real route programming rate: {median:,.0f} routes/s")
    print("[PASS] real kernel route programming benchmark completed")


def test_sanitizer_dns_stress(full_domains, cached_domains, tmpdir):
    banner("TEST 3: CLANG ASAN + UBSAN DNS STRESS")

    requests = env_int("STRESS_REQUESTS", 500000)
    rps = env_int("STRESS_RPS", 50000)
    source_count = min(len(cached_domains), max(1000, min(50000, len(cached_domains))))
    stress_workload = tmpdir / "stress-workload.txt"
    write_lines(
        stress_workload,
        repeated_workload(cached_domains[:source_count], requests, 0x5A17E55),
    )
    blacklist = tmpdir / "blacklist-all-stress.txt"
    blacklist.write_text("0.0.0.0/1\n128.0.0.0/1\n", encoding="ascii")

    result = run_one_antiblock(
        ANTIBLOCK_SANITIZE_BIN,
        full_domains,
        stress_workload,
        rps,
        test_mode=True,
        blacklist=blacklist,
        sanitizer=True,
    )
    responses = result["client_read"]
    if result["processed"] == 0 or responses <= 0:
        raise RuntimeError("sanitizer stress produced no processed DNS responses")
    ratio = 100.0 * result["processed"] / responses

    print(f"  requested           : {requests:,}")
    print(f"  configured rate     : {rps:,} qps")
    print(f"  local response peak : {result['client_peak_read_qps']:,} qps")
    print(f"  client responses    : {responses:,}")
    print(f"  processed           : {result['processed']:,} ({ratio:.2f}%)")
    print(f"  pcap received       : {result['pcap_received']}")
    print(f"  pcap dropped        : {result['pcap_dropped']}")
    print(f"  pcap interface drop : {result['pcap_if_dropped']}")
    print(f"  AntiBlock peak RSS  : {result['peak_rss_kib'] / 1024.0:.1f} MiB")
    print("  ASan                : clean")
    print("  UBSan               : clean")
    print("[PASS] sanitizer DNS stress completed")


def test_sanitizer_route_churn(cached_domains, tmpdir):
    banner("TEST 4: CLANG ASAN + UBSAN REAL ROUTE CHURN STRESS")

    count = min(env_int("ROUTE_STRESS_QUERY_COUNT", 128), len(cached_domains))
    cycles = env_int("ROUTE_STRESS_CYCLES", 10)
    rps = env_int("ROUTE_STRESS_RPS", 20000)
    route_domains = tmpdir / "route-stress-domains.txt"
    route_workload = tmpdir / "route-stress-workload.txt"
    write_lines(route_domains, cached_domains[:count])
    write_lines(route_workload, cached_domains[:count])

    total_routes = 0
    for cycle in range(1, cycles + 1):
        result = run_one_antiblock(
            ANTIBLOCK_SANITIZE_BIN,
            route_domains,
            route_workload,
            rps,
            test_mode=False,
            sanitizer=True,
            route_stable=True,
        )
        routes = result["routes_kernel"]
        if routes <= 0:
            raise RuntimeError(f"cycle {cycle}: no real routes were installed")
        total_routes += routes
        if route_count() != 0:
            raise RuntimeError(
                f"cycle {cycle}: AntiBlock routes remained after cleanup"
            )
        print(f"  cycle {cycle:2d}: added and cleaned {routes:4d} real routes")

    print(f"\n  total real route add/cleanup observations: {total_routes:,}")
    print("  ASan                                   : clean")
    print("  UBSan                                  : clean")
    print("[PASS] sanitizer real-route churn stress completed")


def run_suite(mode):
    full_domains = WORK_DIR / "domains.txt"
    cached_path = WORK_DIR / "out_domains-A.txt"
    cache_path = WORK_DIR / "cache-A.data"

    for path in (full_domains, cached_path, cache_path):
        if not path.exists() or path.stat().st_size == 0:
            raise RuntimeError(f"required prepared file is missing: {path}")

    cached_domains = read_domains(cached_path)
    if len(cached_domains) < 100:
        raise RuntimeError(
            f"only {len(cached_domains)} cached domains are available; "
            "prepare a larger replay cache"
        )

    full_count = sum(1 for _ in full_domains.open("r", encoding="ascii"))
    print("AntiBlock load/stress suite")
    print(f"Full domain table : {full_count:,}")
    print(f"Replay domains    : {len(cached_domains):,}")
    print(f"DNS replay server : {DNS_SERVER}")
    versions = Path("/opt/dns-tools-versions.txt")
    if versions.exists():
        print(versions.read_text(encoding="ascii").rstrip())

    with tempfile.TemporaryDirectory(prefix="antiblock-workloads-") as tmp:
        tmpdir = Path(tmp)
        if mode in ("all", "performance"):
            test_release_dns_throughput(full_domains, cached_domains, tmpdir)
            test_release_route_programming(cached_domains, tmpdir)
        if mode in ("all", "stress"):
            test_sanitizer_dns_stress(full_domains, cached_domains, tmpdir)
            test_sanitizer_route_churn(cached_domains, tmpdir)

    banner("ALL REQUESTED LOAD / STRESS TESTS PASSED")


def main(argv):
    if len(argv) < 2:
        raise RuntimeError("expected prepare or run subcommand")
    command = argv[1]
    if command == "prepare":
        if len(argv) != 4:
            raise RuntimeError(
                "prepare usage: load_test.py prepare INPUT.csv domains.txt"
            )
        prepare_dataset(argv[2], argv[3])
        return 0
    if command == "run":
        mode = argv[2] if len(argv) >= 3 else "all"
        if mode not in ("all", "performance", "stress"):
            raise RuntimeError(f"unknown run mode: {mode}")
        run_suite(mode)
        return 0
    raise RuntimeError(f"unknown subcommand: {command}")


if __name__ == "__main__":
    try:
        raise SystemExit(main(sys.argv))
    except KeyboardInterrupt:
        raise SystemExit(130)
    except Exception as exc:
        print(f"[FAIL] {exc}", file=sys.stderr)
        raise SystemExit(1)
