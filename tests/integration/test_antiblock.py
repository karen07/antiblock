#!/usr/bin/env python3
import collections
import functools
import http.server
import os
import signal
import socket
import struct
import subprocess
import tempfile
import threading
import time
import unittest

ANTIBLOCK_BIN = os.environ.get("ANTIBLOCK_BIN", "/src/build/antiblock")
DNS_IP = "127.0.0.53"
DNS_PORT = 5300
ROUTE_METRIC = "23117"


def run(*args, check=True, capture_output=True, timeout=None):
    return subprocess.run(
        list(args),
        check=check,
        text=True,
        capture_output=capture_output,
        timeout=timeout,
    )


def encode_name(name):
    out = bytearray()
    name = name.rstrip(".")
    if not name:
        return b"\x00"
    for label in name.split("."):
        raw = label.encode("ascii")
        if len(raw) > 63:
            raise ValueError("DNS label too long")
        out.append(len(raw))
        out.extend(raw)
    out.append(0)
    return bytes(out)


def parse_question(packet):
    if len(packet) < 12:
        raise ValueError("short DNS query")
    pos = 12
    labels = []
    while True:
        if pos >= len(packet):
            raise ValueError("truncated qname")
        size = packet[pos]
        pos += 1
        if size == 0:
            break
        if size & 0xC0:
            raise ValueError("compressed query names are not used by this test client")
        if pos + size > len(packet):
            raise ValueError("truncated label")
        labels.append(packet[pos : pos + size].decode("ascii").lower())
        pos += size
    if pos + 4 > len(packet):
        raise ValueError("truncated question")
    return ".".join(labels), pos + 4


def rr_a(owner, ip, ttl):
    return ("A", owner, ip, ttl)


def rr_cname(owner, target, ttl):
    return ("CNAME", owner, target, ttl)


def rr_https(owner, priority, target, ttl):
    return ("HTTPS", owner, (priority, target), ttl)


def build_response(query, answers):
    qname, question_end = parse_question(query)
    ident = query[:2]
    header = ident + struct.pack("!HHHHH", 0x8180, 1, len(answers), 0, 0)
    out = bytearray(header)
    out.extend(query[12:question_end])

    for kind, owner, value, ttl in answers:
        out.extend(encode_name(owner))
        if kind == "A":
            rdata = socket.inet_aton(value)
            rtype = 1
        elif kind == "CNAME":
            rdata = encode_name(value)
            rtype = 5
        elif kind == "HTTPS":
            priority, target = value
            rdata = struct.pack("!H", priority) + encode_name(target)
            rtype = 65
        else:
            raise ValueError(kind)
        out.extend(struct.pack("!HHIH", rtype, 1, ttl, len(rdata)))
        out.extend(rdata)
    return bytes(out), qname


def build_query(name, ident=0x4242, qtype=1):
    return (
        struct.pack("!HHHHHH", ident, 0x0100, 1, 0, 0, 0)
        + encode_name(name)
        + struct.pack("!HH", qtype, 1)
    )


def query_question_bytes(query):
    _, question_end = parse_question(query)
    return query[12:question_end]


def raw_dns_header(query, flags=0x8180, qdcount=1, ancount=0, nscount=0, arcount=0):
    return query[:2] + struct.pack("!HHHHH", flags, qdcount, ancount, nscount, arcount)


def raw_rr(owner, rtype, rdata, ttl=30, rdlength=None):
    if rdlength is None:
        rdlength = len(rdata)
    return encode_name(owner) + struct.pack("!HHIH", rtype, 1, ttl, rdlength) + rdata


class FakeDNSServer:
    def __init__(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind((DNS_IP, DNS_PORT))
        self.sock.settimeout(0.1)
        self.lock = threading.Lock()
        self.responses = {}
        self.counts = collections.Counter()
        self.stop_event = threading.Event()
        self.thread = threading.Thread(target=self._loop, daemon=True)

    def start(self):
        self.thread.start()

    def close(self):
        self.stop_event.set()
        self.thread.join(timeout=2)
        self.sock.close()

    def set_responses(self, name, response_sequence):
        """Each item is either an answer-list or a callable(query)->raw response."""
        with self.lock:
            self.responses[name.lower()] = list(response_sequence)
            self.counts[name.lower()] = 0

    def _response_spec_for(self, name):
        name = name.lower()
        with self.lock:
            seq = self.responses.get(name, [[]])
            index = self.counts[name]
            self.counts[name] += 1
            if index >= len(seq):
                index = len(seq) - 1
            return seq[index]

    def _loop(self):
        while not self.stop_event.is_set():
            try:
                query, peer = self.sock.recvfrom(4096)
            except socket.timeout:
                continue
            try:
                name, _ = parse_question(query)
                spec = self._response_spec_for(name)
                if callable(spec):
                    response = spec(query)
                else:
                    response, _ = build_response(query, spec)
                self.sock.sendto(response, peer)
            except Exception:
                # Malformed test traffic should not kill the fake server thread.
                continue


def dns_query(name, ident=0x4242, qtype=1):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(1.0)
    try:
        sock.sendto(build_query(name, ident, qtype), (DNS_IP, DNS_PORT))
        sock.recvfrom(4096)
    finally:
        sock.close()


def route_show(ip):
    result = run("ip", "-4", "route", "show", f"{ip}/32", check=False)
    return result.stdout.strip()


def wait_until(predicate, timeout=3.0, interval=0.05, message="condition not met"):
    deadline = time.monotonic() + timeout
    last = None
    while time.monotonic() < deadline:
        last = predicate()
        if last:
            return
        time.sleep(interval)
    raise AssertionError(f"{message}; last={last!r}")


def wait_route(ip, *fragments, timeout=3.0):
    def present():
        text = route_show(ip)
        if text and all(fragment in text for fragment in fragments):
            return text
        return False

    wait_until(present, timeout=timeout, message=f"route {ip} missing {fragments}")


def wait_no_route(ip, timeout=4.0):
    wait_until(
        lambda: route_show(ip) == "",
        timeout=timeout,
        message=f"route {ip} still exists",
    )


class QuietHTTPRequestHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        # Simulate an origin that accepts the connection but never responds.
        # Longer than the 2-second HTTP timeout used by the test binaries.
        if self.path == "/stall-domains.txt":
            time.sleep(10)
            return
        super().do_GET()

    def log_message(self, format, *args):
        del format, args


class AntiBlockIntegration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if os.geteuid() != 0:
            raise unittest.SkipTest(
                "integration tests require root inside the container"
            )
        if not os.path.exists(ANTIBLOCK_BIN):
            raise RuntimeError(f"AntiBlock binary not found: {ANTIBLOCK_BIN}")

        cls.tmp = tempfile.TemporaryDirectory(prefix="antiblock-it-")
        cls.root = cls.tmp.name
        cls.rule0 = os.path.join(cls.root, "rule0.txt")
        cls.rule1 = os.path.join(cls.root, "rule1.txt")
        cls.rule_l3 = os.path.join(cls.root, "rule-l3.txt")
        cls.blacklist = os.path.join(cls.root, "blacklist.txt")
        cls.http_domains = os.path.join(cls.root, "http-domains.txt")

        with open(cls.rule0, "w", encoding="ascii") as fp:
            fp.write(
                "blocked.test\n"
                "cname.test\n"
                "learned-origin.test\n"
                "reverse.test\n"
                "ttl.test\n"
                "refresh.test\n"
                "shorter.test\n"
                "move-a.test\n"
                "move-short-a.test\n"
                "cleanup.test\n"
                "blacklist.test\n"
                "custom-blacklist.test\n"
                "MixedCase.Test\n"
                "WWW.UpperWWW.Test\n"
                "!WWW.ExactWWW.Test\n"
                "parent.test\n"
                "!exact.test\n"
                "cname-ttl-origin.test\n"
                "malformed.test\n"
                "test-mode.test\n"
                "telemetry.test\n"
                "gateway-metric.test\n"
                "id-a.test\n"
                "id-b.test\n"
                "additional.test\n"
                "chain-origin.test\n"
                "learned-sub-origin.test\n"
                "www.www-normalized.test\n"
                "crlf.test\r\n"
                "sigint.test\n"
                "https-alias.test\n"
                "https-service.test\n"
                "https-chain.test\n"
            )
        with open(cls.rule1, "w", encoding="ascii") as fp:
            fp.write("move-b.test\nmove-short-b.test\n")
        with open(cls.rule_l3, "w", encoding="ascii") as fp:
            fp.write("l3.test\n")
        with open(cls.blacklist, "w", encoding="ascii") as fp:
            fp.write("11.22.34.0/24\n")
        with open(cls.http_domains, "w", encoding="ascii") as fp:
            fp.write("http-source.test\n")

        handler = functools.partial(QuietHTTPRequestHandler, directory=cls.root)
        cls.httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
        cls.http_port = cls.httpd.server_address[1]
        cls.http_thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.http_thread.start()

        cls._setup_links()
        cls.dns = FakeDNSServer()
        cls.dns.start()

    @classmethod
    def tearDownClass(cls):
        cls.dns.close()
        cls.httpd.shutdown()
        cls.httpd.server_close()
        cls.http_thread.join(timeout=2)
        run("ip", "-4", "route", "flush", "metric", ROUTE_METRIC, check=False)
        run("ip", "-4", "route", "flush", "metric", "22222", check=False)
        run("ip", "link", "del", "ab0", check=False)
        run("ip", "link", "del", "ab1", check=False)
        cls.tmp.cleanup()

    @classmethod
    def _setup_links(cls):
        run("ip", "link", "del", "ab0", check=False)
        run("ip", "link", "del", "ab1", check=False)

        run("ip", "link", "add", "ab0", "type", "veth", "peer", "name", "ab0p")
        run("ip", "addr", "add", "172.30.0.2/24", "dev", "ab0")
        run("ip", "link", "set", "ab0", "up")
        run("ip", "link", "set", "ab0p", "up")
        run(
            "ip",
            "route",
            "add",
            "default",
            "via",
            "172.30.0.1",
            "dev",
            "ab0",
            "metric",
            "32000",
        )

        run("ip", "link", "add", "ab1", "type", "veth", "peer", "name", "ab1p")
        run("ip", "addr", "add", "172.31.0.2/24", "dev", "ab1")
        run("ip", "link", "set", "ab1", "up")
        run("ip", "link", "set", "ab1p", "up")
        run(
            "ip",
            "route",
            "add",
            "default",
            "via",
            "172.31.0.1",
            "dev",
            "ab1",
            "metric",
            "32001",
        )

    def _default_rules(self):
        return [
            ("ab0", self.rule0),
            ("ab1", self.rule1),
            ("lo", self.rule_l3),
        ]

    def _start_antiblock(self, rules=None, extra_args=None):
        if rules is None:
            rules = self._default_rules()
        if extra_args is None:
            extra_args = []

        argv = [ANTIBLOCK_BIN, "-l", f"{DNS_IP}:{DNS_PORT}"]
        for ifname, source in rules:
            argv.extend(["-r", f"{ifname} {source}"])
        argv.extend(["-o", self.outdir.name, "--log", "--stat"])
        argv.extend(extra_args)

        self.proc = subprocess.Popen(
            argv,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        time.sleep(0.35)
        if self.proc.poll() is not None:
            stdout, stderr = self.proc.communicate()
            self.proc = None
            self.fail(
                f"AntiBlock exited during startup\nstdout:\n{stdout}\nstderr:\n{stderr}"
            )

    def _stop_antiblock(self, sig=signal.SIGTERM):
        if self.proc is None:
            return
        if self.proc.poll() is None:
            self.proc.send_signal(sig)
            try:
                self.proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait(timeout=2)
        if self.proc.stdout:
            self.proc.stdout.close()
        if self.proc.stderr:
            self.proc.stderr.close()
        self.proc = None

    def _restart_antiblock(self, rules=None, extra_args=None):
        self._stop_antiblock()
        self._start_antiblock(rules=rules, extra_args=extra_args)

    def setUp(self):
        run("ip", "-4", "route", "flush", "metric", ROUTE_METRIC, check=False)
        run("ip", "-4", "route", "flush", "metric", "22222", check=False)
        self.outdir = tempfile.TemporaryDirectory(
            prefix="antiblock-out-", dir=self.root
        )
        self.proc = None
        self._start_antiblock()

    def tearDown(self):
        self._stop_antiblock()
        run(
            "ip",
            "route",
            "del",
            "default",
            "via",
            "172.30.0.9",
            "dev",
            "ab0",
            "metric",
            "31000",
            check=False,
        )
        run(
            "ip",
            "route",
            "replace",
            "default",
            "via",
            "172.30.0.1",
            "dev",
            "ab0",
            "metric",
            "32000",
            check=False,
        )
        run(
            "ip",
            "route",
            "replace",
            "default",
            "via",
            "172.31.0.1",
            "dev",
            "ab1",
            "metric",
            "32001",
            check=False,
        )
        run("ip", "-4", "route", "flush", "metric", ROUTE_METRIC, check=False)
        run("ip", "-4", "route", "flush", "metric", "22222", check=False)
        self.outdir.cleanup()

    def set_dns(self, name, *responses):
        self.dns.set_responses(name, list(responses))

    def set_raw_dns(self, name, *builders):
        self.dns.set_responses(name, list(builders))

    def assert_process_alive(self):
        self.assertIsNotNone(self.proc)
        self.assertIsNone(self.proc.poll(), "AntiBlock unexpectedly exited")

    def assert_malformed_rejected_and_recovers(self, builder, ip):
        self.set_raw_dns("malformed.test", builder)
        dns_query("malformed.test")
        time.sleep(0.15)
        self.assert_process_alive()
        self.assertEqual(route_show(ip), "")

        self.set_dns("malformed.test", [rr_a("malformed.test", ip, 30)])
        dns_query("malformed.test", ident=0x5A5A)
        wait_route(ip, "dev ab0")

    def test_01_direct_a_adds_l2_route(self):
        ip = "11.22.33.40"
        self.set_dns("blocked.test", [rr_a("blocked.test", ip, 30)])
        dns_query("blocked.test")
        wait_route(ip, "via 172.30.0.1", "dev ab0", f"metric {ROUTE_METRIC}")

    def test_02_unmatched_domain_adds_no_route(self):
        ip = "11.22.33.41"
        self.set_dns("normal.test", [rr_a("normal.test", ip, 30)])
        dns_query("normal.test")
        time.sleep(0.25)
        self.assertEqual(route_show(ip), "")

    def test_03_default_blacklist_blocks_private_a(self):
        ip = "10.20.30.40"
        self.set_dns("blacklist.test", [rr_a("blacklist.test", ip, 30)])
        dns_query("blacklist.test")
        time.sleep(0.25)
        self.assertEqual(route_show(ip), "")

    def test_04_cname_and_a_same_response(self):
        ip = "11.22.33.42"
        self.set_dns(
            "cname.test",
            [rr_cname("cname.test", "cdn.test", 30), rr_a("cdn.test", ip, 30)],
        )
        dns_query("cname.test")
        wait_route(ip, "dev ab0")

    def test_05_learned_cname_routes_later_independent_answer(self):
        ip = "11.22.33.43"
        self.set_dns(
            "learned-origin.test",
            [rr_cname("learned-origin.test", "learned-target.test", 30)],
        )
        self.set_dns("learned-target.test", [rr_a("learned-target.test", ip, 30)])
        dns_query("learned-origin.test")
        time.sleep(0.1)
        dns_query("learned-target.test", ident=0x4243)
        wait_route(ip, "dev ab0")

    def test_06_cname_propagation_is_independent_of_rr_order(self):
        ip = "11.22.33.44"
        self.set_dns(
            "reverse.test",
            [
                rr_a("reverse-target.test", ip, 30),
                rr_cname("reverse.test", "reverse-target.test", 30),
            ],
        )
        dns_query("reverse.test")
        wait_route(ip, "dev ab0")

    def test_07_ttl_expires_route(self):
        ip = "11.22.33.45"
        self.set_dns("ttl.test", [rr_a("ttl.test", ip, 2)])
        dns_query("ttl.test")
        wait_route(ip, "dev ab0")
        wait_no_route(ip, timeout=4.5)

    def test_08_same_gateway_refresh_extends_ttl(self):
        ip = "11.22.33.46"
        self.set_dns(
            "refresh.test",
            [rr_a("refresh.test", ip, 2)],
            [rr_a("refresh.test", ip, 5)],
        )
        dns_query("refresh.test")
        wait_route(ip, "dev ab0")
        time.sleep(1.0)
        dns_query("refresh.test", ident=0x4244)
        time.sleep(1.6)  # Original TTL has passed, refreshed TTL has not.
        self.assertIn("dev ab0", route_show(ip))

    def test_09_latest_dns_observation_moves_dst_between_gateways(self):
        ip = "11.22.33.47"
        self.set_dns("move-a.test", [rr_a("move-a.test", ip, 30)])
        self.set_dns("move-b.test", [rr_a("move-b.test", ip, 30)])
        dns_query("move-a.test")
        wait_route(ip, "dev ab0")
        dns_query("move-b.test", ident=0x4245)
        wait_route(ip, "via 172.31.0.1", "dev ab1")
        self.assertNotIn("dev ab0", route_show(ip))

    def test_10_l3_interface_installs_device_route(self):
        ip = "11.22.33.48"
        self.set_dns("l3.test", [rr_a("l3.test", ip, 30)])
        dns_query("l3.test")
        wait_route(ip, "dev lo")
        self.assertNotIn(" via ", f" {route_show(ip)} ")

    def test_11_dns_names_are_case_insensitive(self):
        ip = "11.22.33.49"
        self.set_dns("mixedcase.test", [rr_a("MIXEDCASE.TEST", ip, 30)])
        dns_query("MIXEDCASE.TEST")
        wait_route(ip, "dev ab0")

    def test_12_sigterm_removes_live_routes(self):
        ip = "11.22.33.50"
        self.set_dns("cleanup.test", [rr_a("cleanup.test", ip, 60)])
        dns_query("cleanup.test")
        wait_route(ip, "dev ab0")

        self.proc.send_signal(signal.SIGTERM)
        self.proc.wait(timeout=3)
        self.assertEqual(self.proc.returncode, 0)
        wait_no_route(ip, timeout=2.0)

    def test_13_same_dns_transaction_id_does_not_drop_different_answer(self):
        ip_a = "11.22.33.51"
        ip_b = "11.22.33.52"
        self.set_dns("id-a.test", [rr_a("id-a.test", ip_a, 30)])
        self.set_dns("id-b.test", [rr_a("id-b.test", ip_b, 30)])
        dns_query("id-a.test", ident=0x7777)
        dns_query("id-b.test", ident=0x7777)
        wait_route(ip_a, "dev ab0")
        wait_route(ip_b, "dev ab0")

    def test_14_startup_cleanup_removes_only_own_metric(self):
        stale_ip = "11.22.33.60"
        foreign_ip = "11.22.33.61"

        self.proc.kill()
        self.proc.wait(timeout=2)
        if self.proc.stdout:
            self.proc.stdout.close()
        if self.proc.stderr:
            self.proc.stderr.close()
        self.proc = None

        run(
            "ip",
            "route",
            "add",
            f"{stale_ip}/32",
            "via",
            "172.30.0.1",
            "dev",
            "ab0",
            "metric",
            ROUTE_METRIC,
        )
        run(
            "ip",
            "route",
            "add",
            f"{foreign_ip}/32",
            "via",
            "172.30.0.1",
            "dev",
            "ab0",
            "metric",
            "22222",
        )

        self._start_antiblock()
        wait_no_route(stale_ip, timeout=2.0)
        self.assertIn("metric 22222", route_show(foreign_ip))

    def test_15_shorter_ttl_does_not_shorten_same_rule_route(self):
        ip = "11.22.33.62"
        self.set_dns(
            "shorter.test",
            [rr_a("shorter.test", ip, 4)],
            [rr_a("shorter.test", ip, 1)],
        )
        dns_query("shorter.test")
        wait_route(ip, "dev ab0")
        time.sleep(0.6)
        dns_query("shorter.test", ident=0x5015)
        time.sleep(1.5)
        self.assertIn("dev ab0", route_show(ip))
        wait_no_route(ip, timeout=4.5)

    def test_16_move_to_new_rule_uses_new_ttl(self):
        ip = "11.22.33.63"
        self.set_dns("move-short-a.test", [rr_a("move-short-a.test", ip, 30)])
        self.set_dns("move-short-b.test", [rr_a("move-short-b.test", ip, 2)])
        dns_query("move-short-a.test")
        wait_route(ip, "dev ab0")
        dns_query("move-short-b.test", ident=0x5016)
        wait_route(ip, "dev ab1")
        wait_no_route(ip, timeout=4.5)

    def test_17_learned_cname_survives_its_dns_ttl(self):
        ip = "11.22.33.64"
        self.set_dns(
            "cname-ttl-origin.test",
            [rr_cname("cname-ttl-origin.test", "cname-ttl-target.test", 1)],
        )
        self.set_dns(
            "cname-ttl-target.test",
            [rr_a("cname-ttl-target.test", ip, 30)],
        )
        dns_query("cname-ttl-origin.test")
        time.sleep(2.0)
        dns_query("cname-ttl-target.test", ident=0x5017)
        wait_route(ip, "dev ab0")

    def test_18_normal_domain_rule_matches_subdomains(self):
        ip = "11.22.33.65"
        self.set_dns("deep.sub.parent.test", [rr_a("deep.sub.parent.test", ip, 30)])
        dns_query("deep.sub.parent.test")
        wait_route(ip, "dev ab0")

    def test_19_exact_domain_rule_rejects_subdomain(self):
        exact_ip = "11.22.33.66"
        sub_ip = "11.22.33.67"
        self.set_dns("exact.test", [rr_a("exact.test", exact_ip, 30)])
        self.set_dns("sub.exact.test", [rr_a("sub.exact.test", sub_ip, 30)])

        dns_query("exact.test")
        wait_route(exact_ip, "dev ab0")
        dns_query("sub.exact.test", ident=0x5019)
        time.sleep(0.25)
        self.assertEqual(route_show(sub_ip), "")

    def test_20_custom_blacklist_file_blocks_route(self):
        ip = "11.22.34.20"
        self._restart_antiblock(extra_args=["-b", self.blacklist])
        self.set_dns("custom-blacklist.test", [rr_a("custom-blacklist.test", ip, 30)])
        dns_query("custom-blacklist.test")
        time.sleep(0.25)
        self.assert_process_alive()
        self.assertEqual(route_show(ip), "")

    def test_21_test_mode_does_not_modify_kernel_routes(self):
        ip = "11.22.33.68"
        self._restart_antiblock(extra_args=["--test"])
        self.set_dns("test-mode.test", [rr_a("test-mode.test", ip, 30)])
        dns_query("test-mode.test")
        time.sleep(0.25)
        self.assert_process_alive()
        self.assertEqual(route_show(ip), "")

    def test_22_log_and_stat_files_are_created(self):
        ip = "11.22.33.69"
        self.set_dns("telemetry.test", [rr_a("telemetry.test", ip, 30)])
        dns_query("telemetry.test")
        wait_route(ip, "dev ab0")
        self._stop_antiblock()

        log_path = os.path.join(self.outdir.name, "log.txt")
        stat_path = os.path.join(self.outdir.name, "stat.txt")
        self.assertTrue(os.path.isfile(log_path))
        self.assertTrue(os.path.isfile(stat_path))
        self.assertGreater(os.path.getsize(log_path), 0)
        self.assertGreater(os.path.getsize(stat_path), 0)

    def test_23_l2_uses_lowest_metric_default_gateway(self):
        ip = "11.22.33.70"
        self._stop_antiblock()
        run(
            "ip",
            "route",
            "add",
            "default",
            "via",
            "172.30.0.9",
            "dev",
            "ab0",
            "metric",
            "31000",
        )
        try:
            self._start_antiblock()
            self.set_dns("gateway-metric.test", [rr_a("gateway-metric.test", ip, 30)])
            dns_query("gateway-metric.test")
            wait_route(ip, "via 172.30.0.9", "dev ab0")
        finally:
            self._stop_antiblock()
            run(
                "ip",
                "route",
                "del",
                "default",
                "via",
                "172.30.0.9",
                "dev",
                "ab0",
                "metric",
                "31000",
                check=False,
            )
            self._start_antiblock()

    def test_24_l2_without_default_gateway_fails_cleanly(self):
        self._stop_antiblock()
        run(
            "ip",
            "route",
            "del",
            "default",
            "via",
            "172.31.0.1",
            "dev",
            "ab1",
            "metric",
            "32001",
        )
        try:
            result = run(
                ANTIBLOCK_BIN,
                "-l",
                f"{DNS_IP}:{DNS_PORT}",
                "-r",
                f"ab1 {self.rule1}",
                "-o",
                self.outdir.name,
                check=False,
                timeout=3,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("has no usable default gateway", result.stderr)
        finally:
            run(
                "ip",
                "route",
                "replace",
                "default",
                "via",
                "172.31.0.1",
                "dev",
                "ab1",
                "metric",
                "32001",
            )
            self._start_antiblock()

    def test_25_http_domain_source_routes_matching_answer(self):
        ip = "11.22.33.71"
        source = f"http://127.0.0.1:{self.http_port}/http-domains.txt"
        self._restart_antiblock(rules=[("lo", source)])
        self.set_dns("http-source.test", [rr_a("http-source.test", ip, 30)])
        dns_query("http-source.test")
        wait_route(ip, "dev lo")

    def test_26_failed_http_source_does_not_crash_process(self):
        ip = "11.22.33.72"
        source = f"http://127.0.0.1:{self.http_port}/missing-domains.txt"
        self._restart_antiblock(rules=[("lo", source)])
        self.set_dns("http-source.test", [rr_a("http-source.test", ip, 30)])
        dns_query("http-source.test")
        time.sleep(0.25)
        self.assert_process_alive()
        self.assertEqual(route_show(ip), "")

    def test_27_malformed_short_dns_header_is_rejected(self):
        ip = "11.22.35.27"
        self.assert_malformed_rejected_and_recovers(
            lambda q: q[:2] + b"\x81\x80\x00", ip
        )

    def test_28_malformed_non_response_dns_is_rejected(self):
        ip = "11.22.35.28"

        def builder(query):
            return raw_dns_header(query, flags=0x0100) + query_question_bytes(query)

        self.assert_malformed_rejected_and_recovers(builder, ip)

    def test_29_malformed_question_count_is_rejected(self):
        ip = "11.22.35.29"
        self.assert_malformed_rejected_and_recovers(
            lambda q: raw_dns_header(q, qdcount=0), ip
        )

    def test_30_malformed_question_pointer_out_of_bounds_is_rejected(self):
        ip = "11.22.35.30"

        def builder(query):
            return raw_dns_header(query) + b"\xc0\xff" + struct.pack("!HH", 1, 1)

        self.assert_malformed_rejected_and_recovers(builder, ip)

    def test_31_malformed_question_pointer_loop_is_rejected(self):
        ip = "11.22.35.31"

        def builder(query):
            return raw_dns_header(query) + b"\xc0\x0c" + struct.pack("!HH", 1, 1)

        self.assert_malformed_rejected_and_recovers(builder, ip)

    def test_32_malformed_truncated_question_is_rejected(self):
        ip = "11.22.35.32"

        def builder(query):
            return raw_dns_header(query) + encode_name("malformed.test") + b"\x00\x01"

        self.assert_malformed_rejected_and_recovers(builder, ip)

    def test_33_malformed_truncated_rr_header_is_rejected(self):
        ip = "11.22.35.33"

        def builder(query):
            return (
                raw_dns_header(query, ancount=1)
                + query_question_bytes(query)
                + encode_name("malformed.test")
                + b"\x00\x01\x00"
            )

        self.assert_malformed_rejected_and_recovers(builder, ip)

    def test_34_malformed_rr_rdata_past_packet_is_rejected(self):
        ip = "11.22.35.34"

        def builder(query):
            return (
                raw_dns_header(query, ancount=1)
                + query_question_bytes(query)
                + raw_rr("malformed.test", 1, b"\x0b\x16", rdlength=4)
            )

        self.assert_malformed_rejected_and_recovers(builder, ip)

    def test_35_malformed_a_rdlength_is_rejected(self):
        ip = "11.22.35.35"

        def builder(query):
            return (
                raw_dns_header(query, ancount=1)
                + query_question_bytes(query)
                + raw_rr("malformed.test", 1, b"\x0b\x16\x23")
            )

        self.assert_malformed_rejected_and_recovers(builder, ip)

    def test_36_malformed_cname_pointer_out_of_bounds_is_rejected(self):
        ip = "11.22.35.36"

        def builder(query):
            return (
                raw_dns_header(query, ancount=1)
                + query_question_bytes(query)
                + raw_rr("malformed.test", 5, b"\xc0\xff")
            )

        self.assert_malformed_rejected_and_recovers(builder, ip)

    def test_37_malformed_cname_rdlength_mismatch_is_rejected(self):
        ip = "11.22.35.37"

        def builder(query):
            rdata = encode_name("target.test") + b"\x00"
            return (
                raw_dns_header(query, ancount=1)
                + query_question_bytes(query)
                + raw_rr("malformed.test", 5, rdata)
            )

        self.assert_malformed_rejected_and_recovers(builder, ip)

    def test_38_malformed_reserved_label_encoding_is_rejected(self):
        ip = "11.22.35.38"

        def builder(query):
            return raw_dns_header(query) + b"\x40bad" + struct.pack("!HH", 1, 1)

        self.assert_malformed_rejected_and_recovers(builder, ip)

    def test_39_malformed_question_label_past_packet_is_rejected(self):
        ip = "11.22.35.39"

        def builder(query):
            del query
            template = build_query("malformed.test")
            return raw_dns_header(template) + b"\x05abc"

        self.assert_malformed_rejected_and_recovers(builder, ip)

    def test_40_malformed_question_pointer_missing_second_byte_is_rejected(self):
        ip = "11.22.35.40"

        def builder(query):
            return raw_dns_header(query) + b"\xc0"

        self.assert_malformed_rejected_and_recovers(builder, ip)

    def test_41_malformed_answer_owner_pointer_missing_second_byte_is_rejected(self):
        ip = "11.22.35.41"

        def builder(query):
            return (
                raw_dns_header(query, ancount=1) + query_question_bytes(query) + b"\xc0"
            )

        self.assert_malformed_rejected_and_recovers(builder, ip)

    def test_42_malformed_cname_target_truncated_label_is_rejected(self):
        ip = "11.22.35.42"

        def builder(query):
            return (
                raw_dns_header(query, ancount=1)
                + query_question_bytes(query)
                + raw_rr("malformed.test", 5, b"\x05abc")
            )

        self.assert_malformed_rejected_and_recovers(builder, ip)

    def test_43_malformed_oversized_decoded_name_is_rejected(self):
        ip = "11.22.35.43"

        def builder(query):
            labels = b"".join(b"\x3f" + (bytes([ch]) * 63) for ch in b"abcd")
            qname = labels + b"\x01x\x00"
            return raw_dns_header(query) + qname + struct.pack("!HH", 1, 1)

        self.assert_malformed_rejected_and_recovers(builder, ip)

    def test_44_valid_additional_opt_section_does_not_break_answer_processing(self):
        ip = "11.22.33.73"

        def builder(query):
            response, _ = build_response(query, [rr_a("additional.test", ip, 30)])
            response = bytearray(response)
            response[10:12] = struct.pack("!H", 1)
            # Root owner, OPT type, UDP payload size, ext-rcode/version/flags, RDLENGTH=0.
            response.extend(b"\x00" + struct.pack("!HHIH", 41, 1232, 0, 0))
            return bytes(response)

        self.set_raw_dns("additional.test", builder)
        dns_query("additional.test")
        wait_route(ip, "dev ab0")
        self.assert_process_alive()

    def test_45_multihop_cname_propagates_independent_of_rr_order(self):
        ip = "11.22.33.74"
        self.set_dns(
            "chain-origin.test",
            [
                rr_a("chain-target.test", ip, 30),
                rr_cname("chain-middle.test", "chain-target.test", 30),
                rr_cname("chain-origin.test", "chain-middle.test", 30),
            ],
        )
        dns_query("chain-origin.test")
        wait_route(ip, "dev ab0")

    def test_46_learned_cname_mapping_matches_target_subdomains(self):
        ip = "11.22.33.75"
        self.set_dns(
            "learned-sub-origin.test",
            [rr_cname("learned-sub-origin.test", "learned-base.test", 30)],
        )
        self.set_dns(
            "child.learned-base.test",
            [rr_a("child.learned-base.test", ip, 30)],
        )
        dns_query("learned-sub-origin.test")
        time.sleep(0.1)
        dns_query("child.learned-base.test", ident=0x5046)
        wait_route(ip, "dev ab0")

    def test_47_leading_www_in_domain_list_is_normalized(self):
        ip = "11.22.33.76"
        self.set_dns("www-normalized.test", [rr_a("www-normalized.test", ip, 30)])
        dns_query("www-normalized.test")
        wait_route(ip, "dev ab0")

    def test_48_crlf_domain_list_line_is_parsed(self):
        ip = "11.22.33.77"
        self.set_dns("crlf.test", [rr_a("crlf.test", ip, 30)])
        dns_query("crlf.test")
        wait_route(ip, "dev ab0")

    def test_49_sigint_removes_live_routes(self):
        ip = "11.22.33.78"
        self.set_dns("sigint.test", [rr_a("sigint.test", ip, 60)])
        dns_query("sigint.test")
        wait_route(ip, "dev ab0")

        self.proc.send_signal(signal.SIGINT)
        self.proc.wait(timeout=3)
        self.assertEqual(self.proc.returncode, 0)
        wait_no_route(ip, timeout=2.0)

    def test_50_https_aliasmode_learns_target_for_later_a(self):
        ip = "11.22.33.79"
        self.set_dns(
            "https-alias.test",
            [rr_https("https-alias.test", 0, "https-alias-target.test", 30)],
        )
        self.set_dns(
            "https-alias-target.test",
            [rr_a("https-alias-target.test", ip, 30)],
        )

        dns_query("https-alias.test", qtype=65)
        time.sleep(0.1)
        dns_query("https-alias-target.test", ident=0x5050)
        wait_route(ip, "dev ab0")

    def test_51_https_servicemode_target_is_not_learned(self):
        ip = "11.22.33.80"
        self.set_dns(
            "https-service.test",
            [rr_https("https-service.test", 1, "https-service-target.test", 30)],
        )
        self.set_dns(
            "https-service-target.test",
            [rr_a("https-service-target.test", ip, 30)],
        )

        dns_query("https-service.test", qtype=65)
        time.sleep(0.1)
        dns_query("https-service-target.test", ident=0x5051)
        time.sleep(0.25)
        self.assertEqual(route_show(ip), "")

    def test_52_https_aliasmode_and_cname_chain_is_order_independent(self):
        ip = "11.22.33.81"
        self.set_dns(
            "https-chain.test",
            [
                rr_a("https-chain-target.test", ip, 30),
                rr_https("https-chain-middle.test", 0, "https-chain-target.test", 30),
                rr_cname("https-chain.test", "https-chain-middle.test", 30),
            ],
        )
        dns_query("https-chain.test", qtype=65)
        wait_route(ip, "dev ab0")

    def test_53_malformed_https_alias_compressed_target_is_rejected(self):
        ip = "11.22.35.53"

        def builder(query):
            # HTTPS TargetName must be uncompressed in SVCB/HTTPS RDATA.
            rdata = struct.pack("!H", 0) + b"\xc0\x0c"
            return (
                raw_dns_header(query, ancount=1)
                + query_question_bytes(query)
                + raw_rr("malformed.test", 65, rdata)
            )

        self.assert_malformed_rejected_and_recovers(builder, ip)

    def test_54_help_reports_release_version(self):
        result = run(ANTIBLOCK_BIN, "--help", check=False, timeout=3)
        self.assertEqual(result.returncode, 0)
        self.assertIn("AntiBlock 3.0.0", result.stdout)
        self.assertIn('-r "iface source"', result.stdout)

    def test_55_failed_http_source_retries_after_short_interval(self):
        ip = "11.22.33.73"
        path = os.path.join(self.root, "http-retry-domains.txt")
        source = f"http://127.0.0.1:{self.http_port}/http-retry-domains.txt"
        self._restart_antiblock(rules=[("lo", source)])
        self.set_dns("http-retry.test", [rr_a("http-retry.test", ip, 30)])
        dns_query("http-retry.test")
        self.assertEqual(route_show(ip), "")

        with open(path, "w", encoding="ascii") as fp:
            fp.write("http-retry.test\n")

        def recovered():
            dns_query("http-retry.test")
            return "dev lo" in route_show(ip)

        wait_until(
            recovered,
            timeout=7.0,
            interval=0.2,
            message="HTTP domain source did not recover on retry",
        )
        self.assert_process_alive()

        # After recovery, the next reload should be scheduled in 24 hours,
        # not after another short retry interval.
        os.unlink(path)
        time.sleep(2.5)
        next_ip = "11.22.33.74"
        self.set_dns("http-retry.test", [rr_a("http-retry.test", next_ip, 30)])
        dns_query("http-retry.test")
        wait_route(next_ip, "dev lo")

    def test_56_stalled_http_source_times_out_and_local_rule_still_works(self):
        ip = "11.22.33.75"
        source = f"http://127.0.0.1:{self.http_port}/stall-domains.txt"
        started = time.monotonic()

        # First source never responds. AntiBlock should still finish reloading
        # and load the following local source with no extra table retained.
        self._restart_antiblock(rules=[("lo", source), ("ab0", self.rule0)])
        self.set_dns("blocked.test", [rr_a("blocked.test", ip, 30)])

        def active():
            dns_query("blocked.test")
            return "dev ab0" in route_show(ip)

        wait_until(
            active,
            timeout=7.0,
            interval=0.2,
            message="DNS processing did not resume after HTTP timeout",
        )
        elapsed = time.monotonic() - started
        self.assertGreater(elapsed, 1.0, "HTTP test endpoint did not stall")
        self.assertLess(elapsed, 7.5, "HTTP request exceeded test timeout budget")
        self.assert_process_alive()

    def test_57_empty_first_domain_file_is_safe_with_sanitizers(self):
        empty = os.path.join(self.root, "empty-domains.txt")
        with open(empty, "wb"):
            pass

        # The arena is initially NULL: a zero-byte fread must not form NULL + 0.
        self._restart_antiblock(rules=[("lo", empty)])
        self.assert_process_alive()

        # An empty source must not prevent loading the following nonempty source.
        self._restart_antiblock(rules=[("lo", empty), ("ab0", self.rule0)])
        ip = "11.22.33.90"
        self.set_dns("blocked.test", [rr_a("blocked.test", ip, 30)])
        dns_query("blocked.test")
        wait_route(ip, "dev ab0")
        self.assert_process_alive()

    def test_58_uppercase_www_prefix_in_list_is_normalized(self):
        ip = "11.22.33.91"
        self.set_dns("upperwww.test", [rr_a("upperwww.test", ip, 30)])
        dns_query("upperwww.test")
        wait_route(ip, "dev ab0")

    def test_59_exact_rule_with_uppercase_www_does_not_match_subdomain(self):
        ip = "11.22.33.92"
        self.set_dns("exactwww.test", [rr_a("exactwww.test", ip, 30)])
        dns_query("exactwww.test")
        wait_route(ip, "dev ab0")

        other_ip = "11.22.33.93"
        self.set_dns(
            "child.exactwww.test",
            [rr_a("child.exactwww.test", other_ip, 30)],
        )
        dns_query("child.exactwww.test")
        time.sleep(0.25)
        self.assertEqual(route_show(other_ip), "")
        self.assert_process_alive()

    def test_60_zero_ttl_does_not_create_route(self):
        ip = "11.22.35.94"
        self.set_dns("blocked.test", [rr_a("blocked.test", ip, 0)])
        dns_query("blocked.test", ident=0x5060)
        time.sleep(0.3)
        self.assertEqual(route_show(ip), "")
        self.assert_process_alive()

    def test_61_zero_ttl_does_not_move_existing_route(self):
        ip = "11.22.35.95"
        self.set_dns("move-a.test", [rr_a("move-a.test", ip, 30)])
        self.set_dns("move-b.test", [rr_a("move-b.test", ip, 0)])
        dns_query("move-a.test", ident=0x5061)
        wait_route(ip, "dev ab0")
        dns_query("move-b.test", ident=0x5062)
        time.sleep(0.3)
        self.assertIn("dev ab0", route_show(ip))
        self.assertNotIn("dev ab1", route_show(ip))
        self.assert_process_alive()


if __name__ == "__main__":
    unittest.main(verbosity=2)
