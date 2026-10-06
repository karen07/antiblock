# AntiBlock integration tests

The integration suite builds AntiBlock from source in an `archlinux:latest` Docker image and runs
one Python end-to-end suite against three binaries:

- GCC release;
- Clang release;
- Clang with AddressSanitizer and UndefinedBehaviorSanitizer.

There is intentionally only one shell entry point:

```sh
./tests/integration/run.sh
```

`run.sh` uses Docker layer cache by default, so repeated development runs do not reinstall the Arch
Linux toolchain when only AntiBlock sources changed. For a deliberately clean acceptance rebuild that
also refreshes `archlinux:latest`, run:

```sh
INTEGRATION_NO_CACHE=1 ./tests/integration/run.sh
```

The test binaries override HTTP connect/total timeouts to 1/2 seconds to make stalled-origin
regression tests fast. Production defaults are 5/30 seconds.

The test containers use only `NET_ADMIN` and `NET_RAW`. They do not use host networking or
`--privileged`, so test routes stay inside the container network namespace.

## Test model

The tests exercise the real runtime path:

```text
fake DNS server
      |
      v
UDP DNS response
      |
      v
real libpcap capture
      |
      v
AntiBlock DNS/domain/alias logic
      |
      v
real Linux routing table
```

The same 61 tests run against GCC release, Clang release, and Clang ASan+UBSan. A successful
`run.sh` therefore performs 183 end-to-end test executions.

## Functional and semantic coverage

The suite covers:

- direct A-record routing;
- unmatched domains;
- built-in and custom CIDR blacklist handling;
- CNAME + A in one response;
- learned CNAME use by later independent DNS answers;
- learned CNAME lifetime being independent of the DNS CNAME TTL;
- learned CNAME mappings matching target subdomains;
- multi-hop CNAME propagation;
- CNAME propagation independent of RR order;
- HTTPS AliasMode (`TYPE 65`, `SvcPriority=0`) learning a target for later A answers;
- mixed CNAME + HTTPS AliasMode propagation independent of RR order;
- HTTPS ServiceMode targets not being treated as aliases;
- route TTL expiry;
- TTL=0 records neither adding routes nor moving an existing destination;
- same-rule TTL extension;
- protection from a later shorter TTL for the same route;
- destination moves between routing rules;
- a moved destination using the new rule's TTL;
- L2 routing through a discovered default gateway;
- lowest-metric default-gateway selection;
- clean startup failure for an L2 interface with no default gateway;
- L3 device routes;
- case-insensitive DNS names;
- normal domain rules matching subdomains;
- exact-only (`!domain`) rules rejecting subdomains;
- leading `www.` normalization in domain lists;
- CRLF domain-list parsing;
- empty first domain list under UBSan (including a following nonempty source);
- case-insensitive leading `WWW.` normalization, including exact-only rules;
- `--test` mode leaving the kernel routing table untouched;
- `--log` and `--stat` output creation;
- HTTP domain-list loading;
- HTTP source failure handling and recovery on retry (2-second test interval);
- zero-length libcurl write callbacks (tested separately by sanitized unit tests);
- stalled HTTP origin total timeout (2 seconds in test builds; 30 seconds in production)
  without blocking subsequent local domain sources;
- SIGTERM cleanup;
- SIGINT cleanup;
- repeated 16-bit DNS transaction IDs;
- startup cleanup touching only AntiBlock-owned metric routes;
- the release version/help output;
- valid DNS responses containing an Additional OPT section.

## Malformed DNS regression tests

The defensive checks remain in the C parser. Python does not replace those checks; it constructs
malformed DNS packets that deliberately reach the parser through the normal UDP/libpcap path.

For every malformed packet the common assertion verifies:

1. AntiBlock is still alive;
1. no incorrect route was installed;
1. a valid DNS response sent immediately afterwards is still processed successfully.

The malformed cases cover:

- a truncated DNS header;
- a packet without the response flag;
- an invalid question count;
- a question compression pointer outside the packet;
- a compression-pointer loop;
- a truncated question fixed part;
- a question label extending past the packet;
- a compression pointer missing its second byte;
- a truncated RR header;
- a truncated answer owner/compression pointer;
- RDATA extending past the packet;
- an A record with invalid RDLENGTH;
- a CNAME compression pointer outside the packet;
- a CNAME whose encoded name does not consume exactly RDLENGTH;
- a truncated CNAME target label;
- a compressed HTTPS AliasMode TargetName, which RFC 9460 forbids;
- reserved/invalid DNS label encoding;
- a decoded DNS name that would exceed the parser output buffer.

The ASan+UBSan run makes these tests especially useful for detecting memory-safety and undefined
behavior regressions.

## Relation to the old C parser test

AntiBlock 2.x had a large in-process `dns_ans_check_test()` that called private parser functions and
checked implementation-specific return codes. AntiBlock 3.0.0 no longer has that private API, so the
old function itself is intentionally not kept.

Its protocol-level safety cases are preserved as Python end-to-end regressions. Tests that existed
only to mutate the old `memory_t.max_size` implementation are represented by malformed/oversized DNS
name tests against the current fixed-size parser buffers instead.

The old `DNS_ANS_CHECK_NOT_END_ERROR` expectation is intentionally not copied literally. A DNS
message may legally contain Authority and Additional sections after the Answer section. The suite
instead verifies that a valid response with an Additional OPT record is accepted and still produces
the expected route.
