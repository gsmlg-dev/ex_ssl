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
| P2.1 identity loading | ex_ssl `a9c5713` | verified | Internal loader, role-aware key matching, bounded DER/PEM and redaction. 78 tests+5 properties pass; public options remain unsupported until P2.2. |
| P2.2 client authentication | ex_ssl `fc1319d` | verified | Public identity options, authenticated request selection, fragmented client flight and original-deadline/cancellation cleanup. Seed53:240 tests+11 properties, zero failures. |
| P2.3 HTTP mTLS | ex_ssl `fc1319d`, http_fetch `cbbc2f6` | verified | 30 source-candidate tests;442 root consumer tests+20 doctests,zero failures. Exact identities, required/optional negatives, redirect scope, WSS and deterministic SSE reconnect. |
| P3.1 policy/profile options | ex_ssl `509f002` | verified | Explicit ordered policies, exact profile conflicts and enforced issuer-signature policy. Full local library seed61:438tests+15properties pass. 39 packaged candidate tests pass. |
| P3.2 TCP allowlist | ex_ssl `509f002`, http_fetch `f482322` | verified | Full library438tests+15properties;39 packaged candidate tests;442 root consumer tests+20doctests,zero failures. |
| P3.3 advanced certificate policy | both | verified | Production audit has no advanced-policy consumers. Unsupported callback/trust/CRL/OCSP policies explicitly reject; one test exercises nine pre-I/O rejections, seed55. |
| P4.1 TLS 1.2 architecture | ex_ssl `031dcea` ADR + P4 protocol commit | verified | Pure engine dispatch retains runtime; PRF/EMS/AEAD/codecs/signatures independently tested. |
| P4.2 modern TLS 1.2 subset | ex_ssl P4 protocol commit | verified | Four ECDHE-GCM suites, required EMS/reneg indication, bounded full/mTLS and version negotiation. Local OTP28 omits EMS and is deliberately rejected. |
| P4.3 dual-version integration | both | in_progress | Library492tests+16properties pass; packaged HTTP1/2/WSS/SSE gate in progress. OTP positiveTLS12 unavailable under EMS policy; other runtime matrix pending. |
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


### P2.2 initial client-authentication flight

Public identity options now feed the pure handshake machine. The client signs
only after authenticating the server flight, derives application keys at the
server-Finished transcript boundary, and includes its exact Certificate and
CertificateVerify bytes in its own Finished. Certificates larger than one record
are fragmented through the existing writer and original connect deadline.
Credentials remain absent without CertificateRequest. Selection applies requested
schemes, CA names, chain signature policy, and leaf digitalSignature eligibility.
Unknown OID filters are ignored; recognized KU/EKU filter value matching remains
unsupported and conservatively selects an empty Certificate. Post-handshake auth
remains unsupported. Self-signed chain roots are exempt from issuer-signature
policy. Documentation states these limits and late peer rejection semantics.

- Public-options initial red: 3 tests, 1 failure. Seed50 options gate:16 tests,
  zero failures. Initial real-peer red:6 tests,3 required-auth failures before
  implementing the flight. OTP reference fixture initially lacked binary mode;
  corrected run executed1 test,7 excluded,zero failures (not eight passing).
- Pure protocol final seed50:74 tests+4 properties,zero failures. Review repaired
  issuer-EC tuple shape, strict DER Names, unknown-OID handling and leaf key usage;
  generic DER filter-value validation was removed for unsupported opaque values.
- Real-peer seed51:9 tests,zero failures: RSA/P256/large identity, P384 HRR,
  OTP reference, optional/no-request and required-identity rejection cases.
- Lifecycle seed160526:2 tests,zero failures. A gated peer plus suspended writer
  proves a queued client-authentication flight larger than16KiB. Bounded state
  probes establish the barrier; no timing assumption creates it. Deadline and
  owner cancellation each assert port, writer, connection and timer cleanup.
  Existing record-gate input-order suite seed329021:6 tests,zero failures.
- Combined seed52:238 tests+11 properties,1 failure from an unvalidated fixture
  assertion that OpenSSL emitted no extensions. It now checks specifically that
  Key Usage is absent; automatically added Subject Key Identifier is allowed.
- Final `MIX_ENV=test mix test test/ssl/client_identity_test.exs
  test/ssl/client_identity_options_test.exs test/ssl/options_test.exs
  test/ssl/protocol test/ssl/crypto/signature_test.exs
  test/ssl/crypto/signature_expansion_test.exs test/ssl/client_auth_interop_test.exs
  test/ssl/client_auth_lifecycle_test.exs test/ssl/connection_interop_test.exs
  test/ssl/http_fetch_transport_contract_test.exs --include integration --seed 53`: **240 tests+11 properties,zero failures**,
  no exclusions. Log `/tmp/ex-ssl-tls-plan-mtls-final.log`.
- Dev/test strict compile, full formatting and diff checks pass. Mandatory
  interop workflow now includes both new mTLS suites; remote matrix not run.

Next incomplete task: P2.3 packaged consumer mTLS and redirect-origin policy.


### P2.3 packaged consumer mTLS and origin scope

The existing SSL option path carries the validated identity to HTTP/1.1, HTTP/2,
WSS and EventSource. The only production change is a redirect guard: ex_ssl client
identities cannot cross the original scheme/normalized host/effective port during
automatic redirect following. Same-origin and manually authorized new requests
retain credentials; OTP behavior, defaults and QUIC are unchanged.

- Packaged HTTP mTLS targeted run:11 tests,zero failures,seed36. Required RSA,
  P256 and >16KiB identity over HTTP1/2; exact peer DER; optional noidentity;
  missing/wrongCA/expired/purpose/scheme failures, pre-I/O mismatch and bad server
  hostname. Initial fixture failures omitted explicit ALPN and accidentally
  returned the helper's port-closure assertion instead of the HTTP response.
  Log `/tmp/http-fetch-tls-plan-mtls.log`. Worker required three repair iterations;
  parent reviewed the resulting code and included it in the combined gate.
- Redirect red:4 tests,1 failure before guard. Intermediate guard run:4 tests,
  1 failure because the old redirect error handler returned the302 response.
  The new policy error now propagates specifically without changing existing
  malformed-redirect behavior. Review added case-normalized origin comparison
  isolated from OTP header handling and a same-origin DNS-case regression.
- Combined `EX_SSL_SOURCE_DIR=/home/gao/Workspace/gsmlg-dev/ex_ssl/.trees/tls-backend-plan
  bash scripts/ex_ssl_source_smoke.sh`: **30 tests,zero failures**,seed36.
  All five fresh package artifacts compile with warnings as errors in an isolated
  consumer; override exists only there. Includes12 prior algorithm tests,11 HTTP
  mTLS tests,5 redirect tests,2 WSS/SSE tests.
  Log `/tmp/http-fetch-tls-plan-candidate-p2.log`.
- Follow-up review strengthened SSE with an explicit pre-EOF close barrier:
  change the global backend to invalid before allowing the first socket to close,
  then verify the pinned ex_ssl reconnect and exact identity. Targeted fresh
  source smoke rerun: **2 tests,zero failures**,seed36. No production change.
- Root scoped `MIX_ENV=test mix test apps/http_core/test apps/http_fetch/test
  apps/http_web_socket/test apps/http_event_source/test apps/http_web_transport/test
  --seed 54`: **442 tests+20 doctests,zero failures**,no exclusions.
  Log `/tmp/http-fetch-tls-plan-p2-regression.log`.
- Dev/test strict compile, format and diff checks pass. Configured `mix credo`
  passes on116files. Additional `mix credo --strict` exited8 with five existing
  low-priority apply/arity findings: QUIC transport line257 and HTTP2 test
  lines91/1637/1648/1685; left unchanged. This extra strict run is not a pass.
- Existing released-dependency smoke remains separate; package dependency metadata
  still targets ex_ssl0.3.0. No source overrides, lock changes or upgrades committed.

Next incomplete task: P3.1 ordered TLS policy/profile option support.


### P3.3 advanced-policy inventory

`rg` over all five consumer production trees found only the existing HTTPS
hostname matcher; no verify_fun, partial_chain, CRL or OCSP caller was found.
The compatibility matrix now states the supported trust/depth/identity boundary
and explicitly rejected advanced policies, using OTP29 public documentation.
`MIX_ENV=test mix test test/ssl/certificate_policy_options_test.exs --seed 55`
passed: **1 test,zero failures**, exercising9 rejected option configurations
before I/O and proving supplied permissive callbacks were never called.
No production behavior changed. Required advanced policy would need a separate
reviewed implementation; none is required by this audited consumer.


### P3.1 / P3.2 library option gates

Added ordered public TLS1.3 suite maps/RFC names, signature/group atoms and
explicit certificate-signature restrictions. Explicit profiles must agree in
order; generated profiles retain requested order. PKIX applies certificate policy
to the validated chain and chosen trust anchor; client-auth selection shares the
same key/curve/PSS metadata logic. No ext50 preserves previous default behavior.
Certificate-only RSA PKCS1 support requires the exact runtime padding primitive.

TCP parsing strips only the validated safe allowlist, rejects conflicts and
unsupported STARTTLS binding/family changes, and preserves raw ownership controls.
Mutable options validate fully before I/O; driver errors leave TLS mode unchanged
but kernel rollback is not promised. Parent review caught an unconditional empty
raw setopts call after TCP cleanup: the deterministic closure regression failed
(1 executed test failed,30 excluded) before virtual-only options were separated.
Local `ip` strings were also incorrectly accepted; a focused red test reproduced
it, then tuple-only validation fixed it. Malformed lists, invalid UTF8 and oversized
driver integers reject explicitly.

- Agent policy focused seed56:142 tests+7 properties,zero failures. Related
  mTLS/connection/P384 seed57:28 tests,zero failures; final padding capability
  review was covered by the subsequent focused rerun and full library gate.
- TCP initial agent gate:6 tests,zero failures. Parent added real IPv6 textual/IP
  SAN/SNI evidence, STARTTLS, OTP reference and forced underlying socket errors.
  Parent seed57:40tests,2 fixture failures (OTP getopts order, assumed spontaneous
  DOWN after externally closing a port); seed58:40tests,1 remaining order failure
  because the first edit did not match formatted source. Corrected comparisons
  use option values; forced-error test verifies unchanged TLS state and explicit
  cleanup. Seed59:41tests,zero failures including all31 transport regressions.
- Final `MIX_ENV=test mix test --include integration --seed 61`: **438 tests and
  15 properties,zero failures,no exclusions**. IPv6 loopback available and tested.
  Log `/tmp/ex-ssl-tls-plan-p3-library.log`.

Next incomplete gate: P3 consumer adapter/source-candidate option coverage.

### P3 consumer gate

Expanded only the adapter TCP allowlist and pre-normalization validation of ex_ssl
keyword containers/duplicates. The initial packaged red ran8tests with5failures
(adapter rejections and malformed-list crash). After the adapter change, targeted
source smoke ran9tests with0failures; full source smoke ran39tests with0failures,
seed36. No edits to the test script after green. Source override remains confined
to the isolated consumer.

Root `MIX_ENV=test mix test apps/http_core/test apps/http_fetch/test
apps/http_web_socket/test apps/http_event_source/test apps/http_web_transport/test
--seed 62` passed442tests+20doctests,zero failures/no exclusions. Log
`/tmp/http-fetch-tls-plan-p3-regression.log`. Dev/test strict compilation, full
format and diff checks passed. Both compatibility documents updated.

Next incomplete task: P4.1 pure TLS1.2 engine under the recorded ADR; public TLS1.2
version acceptance remains disabled until end-to-end proof.

### P4 library implementation and gates

ADR `031dcea` preceded code. Separate pure TLS12 codecs, key schedule and records
implement ECDHE/EMS/AES-GCM; raw signature entry points retain key/curve/PSS checks.
The existing HandshakeMachine dispatch retains exact ClientHello and initial
fragmented/coalesced flight; Connection/writer/deadline/delivery code is unchanged.
Version-aware registry/policy prevents TLS12 suites entering TLS13 crypto. Explicit
profiles retain ordered version/policy validation. Default remainsTLS13-only.

- Pure key schedule/record/raw signature seed60:11tests,zero failures. Existing+
  new signatures seed61:10tests,zero failures. Independent Python HMAC/OpenSSL
  GMAC vectors; one corrected expected AES128 key-block length.
- Codec seed63:9tests+1property,zero failures. Two initial faulty test expectations
  fixed in one repair round. Policy/profile/dispatcher seed66:79tests+1property,
  zero failures, after two repair rounds; TLS12-only earlyCCS explicitly rejected.
- Pure machine red seed63:1test failed missing implementation. Initial OTP28
  positive seed64 failed because ServerHello omitted EMS23; no legacy master-secret
  workaround added. It is retained as an explicit negative test; positive TLS12
  interop uses OpenSSL3.6.3. This runtime cannot satisfy an OTP-positive EMS gate.
- Pure machine+negatives seed67:9tests,zero failures (OpenSSLHTTP, OTPmissingEMS,
  fragmentedSH, signedECDHE, CCS, Finished/AEAD, downgrade and record classifications).
  Review added aggregate/local-flight bounds, echoed-session-ID rejection and
  correct EMS/reneg/unsolicited-extension fatal alerts, covered by final fullgate.
- TLS13 registry-boundary red seed68:9tests,1failure; narrow allTLS13 suite consumers
  and centralizeTLS12 metadata. Green seed69:28tests+1property,zero failures.
- Public OpenSSL peer worker initial13tests/12failures (test public numericciphers),
  next13/7 (fixture abruptclose/childshutdown), next13/4 (JSONnull assertion).
  Two repair rounds exhausted; parent took over. Parent fixes JSONnull to`:null`,
  requires TLS12client-auth failure before connect success, and adds ownership plus
  truncation cleanup. Seed75:15tests/1failure because test expectedclosed instead
  of contractually correcteconnreset. Corrected seed76:**15tests,zero failures**.
- Both-version deterministic blocked large client-flight timeout and owner-cancel
  plus protocol negatives seed73:**12tests,zero failures**. Same explicit record
  gate/writer suspension proves unchanged deadline and connection/writer/port/timer
  cleanup; no timing collision creates the test condition.
- Early fullseed70 caught in-progress peerfixture:486tests+16properties,6failures.
  Final `MIX_ENV=test mix test --include integration --seed 77`: **492tests and
  16properties,zero failures,no exclusions**, log `/tmp/ex-ssl-tls-plan-p4-final.log`.
  Dev/test strictcompile, fullformat and diff checks pass. Remote matrix notrun.

Compatibility docs and mandatory interoperability workflow updated. These are
source-candidate features, not changes to published0.3.0. Next incomplete task:
P4.3 packaged dual-version HTTP1/2, WSS and EventSource evidence.
