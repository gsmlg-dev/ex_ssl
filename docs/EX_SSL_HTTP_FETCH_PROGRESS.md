# ex_ssl / http_fetch implementation ledger

Execution started 2026-09-22. The source plan is
[ex_ssl-http_fetch-implementation-plan.md](ex_ssl-http_fetch-implementation-plan.md).
Only commands recorded in this execution count as current evidence.

## Reconciled revisions

Both origins fetched with `git fetch --prune origin`. ex_ssl checkout main was
`99c09ec510dac0f7dc2d3f135816f3d2ebac326d`; remote main is
`0f16c2cad34236d644b301179725c6614302fbef` (release metadata commit).
http_fetch checkout and open PR #14 are both
`690258ac38e50b0d1a968d9d5e510c560f45f5d4`; main remains
`540225cec69cd2c1e41eb80b956fd6f1a8df7b70`. PR head descends from inspection
baseline `a1312cc40c8d6aad2cb60e750bfba84f9b3ac1cf` and includes the subsequent
completed-early-response upload fix. No reset, merge, or publication performed.

Implementation worktrees: `.trees/tls-backend-plan` in each repository, branch
`codex/tls-backend-plan`, based on the remote revisions above. Existing dirty
worktrees `ex-ssl-http-fetch` and `http-fetch-ex-ssl-integration` are preserved;
their edits and historical ledger results are not evidence for this execution.

Runtime: Elixir 1.18.5, OTP 28 / ERTS 16.4.0.5. Other supported matrix tuples
have not been executed locally.

## Task status

| Task | Repository / base SHA | Status | Current evidence / remaining gaps |
| --- | --- | --- | --- |
| P0.1 consumer inventory | http_fetch `690258a` | verified | Inventory in consumer `docs/ex-ssl-consumer-contract.md`; implemented, deliberately unsupported, missing, and QUIC/test-only surfaces separated. |
| P0.2 deterministic closure | http_fetch `b4414db7d9061c8892483e3bd632aa384a03ac70` | verified | Existing closure and early-response fixes preserved; missing Content-Length, exact-once completion, frame/header bounds fixed. Final seed25:442 tests+20 doctests, zero failures; independent review approved. |
| P0.3 consumer boundary | both bases above | verified | Root-scoped baseline: 422 tests + 20 doctests, zero failures. ex_ssl transport contract: 31 integration tests; interoperability: 15 integration tests, zero failures. |
| P1.1 capability registry | ex_ssl `0175097` | verified | Runtime-filtered registry, separate certificate-chain policy, registry-backed group/cipher negotiation and AEAD. Seed30: 292 tests +13 properties, zero failures. |
| P1.2 algorithm expansion | ex_ssl `5463ad9` | verified | P-384 ECDHE/ECDSA, Ed25519, RSA-PSS-PSS; independent vectors, negatives and constrained peers. |
| P1.3 negotiation evidence | ex_ssl `5463ad9`, http_fetch `93efee0` | verified | 327 library tests+15 properties; 12 external-candidate tests cover10 HTTP exchanges+5 identity negatives, zero failures. Other CI runtime tuples pending. |
| P2.1 identity loading | ex_ssl (identity commit following `5463ad9`) | verified | Internal loader, role-aware key matching, bounded DER/PEM and redaction. 78 tests+5 properties pass; public options remain unsupported until P2.2. |
| P2.2 client authentication | ex_ssl | not_started | Client Certificate/CertificateVerify flight. |
| P2.3 HTTP mTLS | both | not_started | Origin scope and required/optional auth. |
| P3.1 policy/profile options | both | not_started | Ordered registry-backed configuration. |
| P3.2 TCP allowlist | both | not_started | Validation and real socket behavior. |
| P3.3 certificate policy | both | not_started | Explicit supported/unsupported matrix. |
| P4.1 TLS 1.2 architecture | ex_ssl | not_started | ADR before protocol changes. |
| P4.2 modern TLS 1.2 subset | ex_ssl | not_started | Independent ECDHE/AEAD/EMS implementation. |
| P4.3 dual-version integration | both | not_started | Full negative and consumer evidence. |
| P5 resumption/diagnostics | ex_ssl | not_started | Ticket isolation, real resumption, benchmarks. |
| P6 packaging/readiness | http_fetch `b4414db`, ex_ssl `2942433` | in_progress | Consumer package smoke and58 E2E tests pass; Credo and Dialyzer pass. Other runtime matrix, later features, benchmarks/resource campaigns and human security review remain. |

## Executed commands

- Both worktrees: `MIX_ENV=test mix deps.get` — exit 0; existing locked versions
  retained, including consumer ex_ssl 0.3.0. No installed sources modified.
- ex_ssl: `MIX_ENV=test mix compile --warnings-as-errors` — exit 0.
- ex_ssl: `MIX_ENV=test mix test test/ssl/http_fetch_transport_contract_test.exs`
  — exit 0 but **31 tests excluded, zero executed** because the suite is tagged
  integration. This is not a passing acceptance gate; rerun with explicit include.

OTP remains the default consumer backend. There is no backend fallback, replay,
default-policy change, release, or parity claim in this series.

- http_fetch: `MIX_ENV=test mix compile --warnings-as-errors` — exit 0.
- http_fetch: `MIX_ENV=test mix test apps/http_core/test apps/http_fetch/test
  apps/http_web_socket/test apps/http_event_source/test apps/http_web_transport/test
  --seed 22` — exit 0: respectively 168; 171 + 20 doctests; 33; 26; 24 tests,
  all zero failures. Existing unused `events` test warning and dependency erlex
  parser conflict warning observed; neither suppressed or changed.
- ex_ssl: `MIX_ENV=test mix test test/ssl/http_fetch_transport_contract_test.exs
  --include integration --seed 22` — 31 tests, zero failures, no exclusions.
- ex_ssl: `MIX_ENV=test mix test test/ssl/connection_interop_test.exs
  --include integration --seed 22` — 15 tests, zero failures, no exclusions;
  includes OTP and OpenSSL exchanges, authentication negatives, HRR and fragmentation.
- http_fetch: `MIX_ENV=test mix test
  apps/http_fetch/test/http/socket_client_http2_test.exs --seed 23` — 31 tests,
  zero failures after exact-size/version guard changes to private test probe.

### Phase 0 discovered gap

The existing cross-record close fix and pending-upload fix remain correct and
unchanged. The HTTP/2 parser, however, did not validate response Content-Length
before emitting completion. Pure regression run before the fix:
`MIX_ENV=test mix test apps/http_core/test/http/http2_test.exs --seed 0` —
32 tests, **4 failures**, proving short completion, malformed/conflicting length,
short trailer completion, and forbidden DATA acceptance. This blocks the P0.2
gate until corrected and verified. Additional real TLS buffered/streamed
cross-record mismatch tests are being added. An intermediate integration run
selected 3 tests (31 excluded) and failed all 3 on the in-progress error-name
mapping; it is not baseline red evidence or a passing result.

### Phase 0 final evidence

- Additional core regressions for informational/trailer lengths, post-END_STREAM
  frames and u64 bounds: 38 tests, zero failures (seed 0).
- New `http2_limits_test.exs` initial run: 4 tests, **3 failures**, proving
  oversized frame retention, unbounded continuation and whitespace acceptance.
  A first repair rejected oversized length after three header bytes, failing one
  all-split test; final guard waits for the complete nine-byte header.
- Final `MIX_ENV=test mix test apps/http_core/test/http/http2_limits_test.exs
  apps/http_core/test/http/http2_test.exs
  apps/http_fetch/test/http/socket_client_http2_test.exs --seed 24` — core42 and
  consumer34 tests, zero failures, no exclusions.
- Final `MIX_ENV=test mix test apps/http_core/test apps/http_fetch/test
  apps/http_web_socket/test apps/http_event_source/test apps/http_web_transport/test
  --seed 25` — **442 tests +20 doctests, zero failures**, no exclusions.
- Both repositories: format check, `git diff --check`, dev and test compilation
  with `--warnings-as-errors` passed. Consumer Credo passed (116 source files).
- Independent spec and correctness review approved P0 after repairs.
- `bash scripts/external_consumer_smoke.sh` — exit0, five packages built, fresh
  isolated consumer compiled and started, transitive ex_ssl resolved without a
  direct declaration, local TLS smoke passed. Output retained at
  `/tmp/http-fetch-tls-plan-smoke.log`.

Phase0 is complete. The parser corrections apply to shared HTTP/2 framing with
both TLS backends; OTP adapter behavior and backend defaults remain unchanged.
Protocol rationale: RFC9113 sections4.2 and8.1.1; HTTP content/trailer semantics
from RFC9110. Limits are explicit: at most20 decimal digits within unsigned64,
16384-byte inbound frame payload, 65536-byte compressed header block.

- Consumer E2E: `go build -o /tmp/http-fetch-tls-plan-server .` from the Go
  fixture directory — exit0. Started that binary, read its ephemeral port,
  checked HTTP health and ran `MIX_ENV=test E2E_BASE_URL=http://127.0.0.1:<port>
  mix test.e2e` — **58 tests, zero failures**, no exclusions (50 fetch,3 WSS,
  3 WebTransport,2 EventSource), seed344001. Server terminated and reaped afterward.
  Log: `/tmp/http-fetch-tls-plan-e2e.log`.
- Consumer `mix dialyzer --format github` — exit0 after fresh PLT build;
  4 existing ignored diagnostics, 0 unnecessary ignores, no new diagnostics.
  Log: `/tmp/http-fetch-tls-plan-dialyzer.log`.

### P1.1 capability registry

Centralized implemented cipher/signature/group identifiers, key restrictions,
share encoding/size, AEAD/hash metadata, and exact runtime prerequisites.
Handshake decoding may recognize a TLS identifier without advertising it; Ed448
regression proves recognition does not enable verification. Certificate-chain
signature policy remains separate and unenforced; runtime profiles explicitly
reject `signature_algorithms_cert` rather than borrowing handshake capabilities.
No new algorithm or changed backend/version default in this commit.

- Registry initial missing-module regressions: 3 failures. Review found an
  outdated materializer fixture that omitted certificate-chain capabilities;
  fixture now supplies its explicit pure-codec policy (no runtime fallback).
- Additional metadata regression: 5 tests, 1 failure before repair.
- Intermediate focused run: 128 tests +7 properties, zero failures.
- Final `mix test test/ssl/capabilities_test.exs test/ssl/options_test.exs
  test/ssl/client_hello test/ssl/crypto test/ssl/protocol
  test/ssl/connection_interop_test.exs test/ssl/http_fetch_transport_contract_test.exs
  --include integration --seed 30`: **292 tests +13 properties, zero failures**,
  no exclusions. Dev/test warnings-as-errors compile, format and diff checks pass.
- Independent review identified remaining duplicated negotiation mappings;
  ServerHello, HandshakeMachine, ServerFlightVerifier, KeySchedule and AEAD now
  consume the registry. Existing record encryption limits remain separate policy.

Next incomplete task: P1.2 algorithm expansion, followed by P1.3 independent
negotiation and HTTP evidence. Later phases remain unimplemented.

### P1.2 / P1.3 expanded algorithms

Implemented P-384 ECDHE and ECDSA, Ed25519, RSA-PSS-PSS SHA256/384/512.
Leaf OIDs and restricted PSS parameters remain distinct from unrestricted RSA.
Internal client signing uses a separate context; mTLS options/flight are still
unimplemented. Independent review approved the group and signature changes.

- P384 initial unit regressions: 4 tests, 4 failures. First implementation run:
  71 tests +3 properties, 1 failure exposing provider reduction of an out-of-range
  scalar; explicit P384 scalar-range check fixed it.
- P384 peer fixture initially requested unavailable OTP TLS1.3 `selected_group`,
  then pre-TLS1.3 `ecc` diagnostic; both two-test runs failed. Final fixture
  constrains the peer to P384 and proves a complete HTTP exchange instead.
- P384 seed34: 190 tests +13 properties, zero failures; includes direct and HRR
  HTTP exchanges, exact response length, connection death and listener cleanup.
- Signature focused final: 21 tests, zero failures; OpenSSL-generated independent
  signatures, client signing verified with OpenSSL, role/context isolation,
  wrong keys/curves/DER/PSS parameters, and five constrained OTP HTTP exchanges.
  Earlier adjacent run had one stale pre-expansion capability expectation; fixed.
- Final library command: `mix test test/ssl/capabilities_test.exs
  test/ssl/options_test.exs test/ssl/client_hello test/ssl/crypto test/ssl/pkix
  test/ssl/protocol test/ssl/connection_interop_test.exs
  test/ssl/http_fetch_transport_contract_test.exs test/ssl/p384_interop_test.exs
  --include integration --seed 37` — **327 tests +15 properties, zero failures**,
  no exclusions. Dev/test strict compilation and formatting passed.
- Required interoperability workflow now explicitly includes both new integration
  suites; it cannot silently omit all new algorithm tests. Remote CI not run.
- Consumer `EX_SSL_SOURCE_DIR=/home/gao/Workspace/gsmlg-dev/ex_ssl/.trees/tls-backend-plan
  bash scripts/ex_ssl_source_smoke.sh` — exit0, **12 tests, zero failures**, seed36.
  Builds fresh http_core/http_fetch packages, overrides ex_ssl only in a temporary
  isolated consumer, preserves locked quic1.6.5/telemetry1.3.0. Ten positive
  requests cover all five signatures over HTTP1.1+P384 HRR and HTTP2+direct P384;
  five hostname failures remain failures, OTP default is asserted. Initial two
  fixture runs had five HTTP2 failures: the request omitted `http_version: :http2`.
  Correcting explicit HTTP mode/ALPN (and peer SETTINGS-ACK barrier) resolved it;
  no production transport change. Log `/tmp/http-fetch-tls-plan-algorithms.log`.

Next incomplete task: P2.1 bounded client identity loading. Phases2–5 are not
implemented; local gates do not imply full OTP parity or runtime-matrix coverage.

- P6 supporting evidence at ex_ssl `5463ad9`: exact configured interoperability
  workflow file list, with explicit `--include integration --seed 38`, passed
  **112 tests, zero failures, no exclusions** on local OTP28/Elixir1.18.5.
  Covers lifecycle, OTP reference, OTP/OpenSSL interop, new algorithms, depth,
  input ordering, output/backpressure and consumer transport contract.
  Log `/tmp/ex-ssl-tls-plan-interop.log`. Remote matrix remains unexecuted.

### P2.1 bounded identity preparation

Internal ClientIdentity loader supports documented DER/typed-key and unencrypted
PEM forms, binary/charlist paths and one combined PEM. It rejects conflicts,
multiple identities/keys, encrypted/hardware forms, malformed/oversized input,
unordered or duplicate chains, and mismatched keys. Bounds are documented in
COMPATIBILITY.md. Expiration/trust remain the peer's decision; the local loader
checks key matching and ordered chain signatures without trusting the identity.

- Initial missing-module regression run failed; first implementation's eight
  loader tests passed. Parent review found key matching stripped PSS leaf
  restrictions; shared `Signature.verify_client/5` now enforces the same key and
  encoding policy as server verification with the distinct client context.
- Final `MIX_ENV=test mix test test/ssl/client_identity_test.exs
  test/ssl/crypto/signature_test.exs test/ssl/crypto/signature_expansion_test.exs
  test/ssl/pkix test/ssl/protocol/server_flight_verifier_test.exs
  --include integration --seed 44` — **78 tests +5 properties, zero failures**.
- Dev/test warnings-as-errors compilation, formatting and diff checks passed.
  Independent review approved. Different path spellings for the same combined
  PEM may reject; use a single certfile path or the identical path for both.
- Public Options/Connection are intentionally not connected to this loader yet:
  accepting an identity before implementing its flight would silently omit it.

Next incomplete task: P2.2 initial-handshake client authentication.
