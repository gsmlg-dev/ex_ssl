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
| P1.1 capability registry | ex_ssl `0f16c2c` | in_progress | Phase0 gate complete; registry and runtime prerequisite tests in progress. |
| P1.2 algorithm expansion | ex_ssl `0f16c2c` | not_started | P-384, Ed25519, restricted RSA-PSS. |
| P1.3 negotiation evidence | both | not_started | Independent positive/negative handshakes and HTTP. |
| P2.1 identity loading | ex_ssl | not_started | Bounded and redacted client credentials. |
| P2.2 client authentication | ex_ssl | not_started | Client Certificate/CertificateVerify flight. |
| P2.3 HTTP mTLS | both | not_started | Origin scope and required/optional auth. |
| P3.1 policy/profile options | both | not_started | Ordered registry-backed configuration. |
| P3.2 TCP allowlist | both | not_started | Validation and real socket behavior. |
| P3.3 certificate policy | both | not_started | Explicit supported/unsupported matrix. |
| P4.1 TLS 1.2 architecture | ex_ssl | not_started | ADR before protocol changes. |
| P4.2 modern TLS 1.2 subset | ex_ssl | not_started | Independent ECDHE/AEAD/EMS implementation. |
| P4.3 dual-version integration | both | not_started | Full negative and consumer evidence. |
| P5 resumption/diagnostics | ex_ssl | not_started | Ticket isolation, real resumption, benchmarks. |
| P6 packaging/readiness | both | not_started | Matrix, static analysis, packages, smoke, resources; human security review separate. |

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
