# QUIC-TLS implementation ledger

Task source: repository-root `CODEX-PROMPT.md`. Implementation and acceptance evidence are recorded below; the full integration
suite is not claimed green.
Starting branch: `main`; HEAD: `bcb946d40327c68f238df5fd66d945d90f251af4`.
The pre-existing untracked task prompt is preserved. No release/version change,
commit, push or changes to another repository are authorized by this work.

## Current implementation

`SSL.QUIC` now exposes `capabilities/0`, `new/2`, `feed/3`, `info/1`, and `abort/2`.
The client and server use actual fresh ECDHE, certificate signatures and Finished.
TCP and QUIC share `ClientHandshake` for ClientHello/HRR, `HandshakeCore` for
client authentication/secret derivation, and the existing codec/PKIX/crypto
primitives. `ServerFlightVerifier` owns TCP record adaptation; the new
`ServerHandshake` uses the same key-schedule derivation and signature primitives.

The public interface uses caller-owned opaque state and one ordered action list.
Secrets have explicit direction/level/suite/AEAD/hash and redacted inspection.
Transport parameters have separate unverified/authenticated events. Server
completion never claims a client certificate identity. Both input and emitted
handshake bytes consume a bounded cumulative budget. Record-free profiles require
empty session ID and `RecordPolicy.mode: :none`; TCP capabilities accept only the
existing default mode and cannot accidentally emit QUIC parameter extensions.

| Role / transport | Current status |
| --- | --- |
| TCP client, TLS 1.2 | Existing bounded engine retained |
| TCP client, TLS 1.3 | Shared ClientHello/HRR/authentication; existing mTLS/resumption retained |
| Record-free TLS 1.3 client | Real certificate/identity/CV/Finished validation, HRR, directional secrets; independent aioquic peer passed |
| Record-free TLS 1.3 server | Real negotiation/ECDHE/certificate/CV/Finished, HRR and CH2 constraints; no mTLS/resumption/0-RTT; independent aioquic peer passed |
| Record-free post-handshake | Client boundedly parses and discards NST; KeyUpdate/PHA reject in the RFC 9001 error domains |
| Fingerprint public API | `SSL.Fingerprint` direct and fragmented observation; JA3/JA4 from actual bytes, official/reference goldens |
| TCP server | Outside task scope |
| QUIC networking / HTTP/3 | Outside task scope |

## Evidence

Local runtime: Elixir 1.20.1 / OTP 29.0.2.

- Before edits, `mix format --check-formatted`,
  `mix compile --warnings-as-errors`, and `mix test` passed: 394 checks
  (19 properties, 375 tests); 177 integration tests excluded.
- The new raw-core fixture test failed before implementation with
  `UndefinedFunctionError` for `HandshakeCore.start_client/2` (expected red).
- A pre-production-edit `mix test --include integration` run included that
  newly added red test, so it is **not a clean baseline run**. It reported
  570/572 passing: the expected red plus an existing
  `input_ordering_regression_test.exs:325` reference-server failure (expected
  `{:error, :closed}`, got `{:ok, "pending-output"}`).
- Focused extraction tests passed: 71 checks (3 properties, 68 tests), covering
  server-flight verification, handshake machine, resumption verifier/HRR and
  client authentication. Two compile warnings found during extraction were
  corrected.
- Post-extraction `mix format --check-formatted` and
  `mix compile --warnings-as-errors` passed.
- Post-extraction `mix test --include integration`: 571/572 passed (19
  properties, 553 tests). The sole failure is the same pre-existing
  `input_ordering_regression_test.exs:325` peer assertion described above. This
  is a failed full-suite gate, not a passing integration claim.
- After adding two more raw-core authentication negative tests, `mix test`
  passed all 397 checks (19 properties, 378 tests); 177 integration tests
  excluded. Format and warnings-as-errors compile passed in the same command.
  `git diff --check` passed. The two additional tests are default tests and were
  not part of the preceding 572-check integration run.

The raw-core test uses the existing independently constructed SHA-384 fixture:
application key outputs, exact encrypted client Finished and final transcript
digest must match. It also checks that core secrets contain no record states and
ordinary result inspection does not disclose the application secret.
Additional raw-core tests reject wrong trust, wrong reference identity, altered
CertificateVerify and altered Finished, and check incremental-state inspection.

Focused command:

```sh
mix test test/ssl/protocol/server_flight_verifier_test.exs \
  test/ssl/protocol/handshake_machine_test.exs \
  test/ssl/protocol/resumption_verifier_test.exs \
  test/ssl/protocol/resumption_hrr_test.exs \
  test/ssl/protocol/client_authentication_test.exs
```

Local diagnostic logs (not release artifacts) are
`/tmp/ex_ssl-quic-baseline-integration.log`, `/tmp/ex_ssl-quic-core-red.log`,
`/tmp/ex_ssl-quic-core-green.log`, `/tmp/ex_ssl-quic-core-all.log`, and
`/tmp/ex_ssl-quic-core-default.log`. The integration failure existed before
production edits and was not weakened or removed. The new shared core has no
`Record`, `TrafficState`, socket, Logger or process calls; the TCP adapter still
owns the record epochs and the existing connection owns delivery barriers.

## Duplex API validation (second implementation slice)

- `mix format --check-formatted` and `mix compile --warnings-as-errors`: passed.
- `mix test`: **413 passed** (19 properties, 394 tests), 177 integration tests
  excluded. Log: `/tmp/ex_ssl-quic-phase2-default.log`.
- `mix test --include integration`: **588/590 passed** (19 properties, 571
  tests). Log: `/tmp/ex_ssl-quic-phase2-integration.log`. Failures:
  1. The previously observed `input_ordering_regression_test.exs:325` peer
     closure assertion (`pending-output`).
  2. `connection_backpressure_test.exs:9`: `KeyUpdate was not queued behind output`.
     A focused rerun reproduced this; a **clean detached HEAD** worktree at
     `.trees/quic-baseline-audit` also reproduced the same test/error, establishing
     a baseline failure rather than assuming it. Baseline command:
     `mix test --include integration test/ssl/connection_backpressure_test.exs:9`.
     Logs: `/tmp/ex_ssl-quic-backpressure-recheck.log` and
     `/tmp/ex_ssl-quic-clean-baseline-backpressure.log`.
- After the shared repeated-HRR classification correction, focused
  `mix test test/ssl/quic_test.exs test/ssl/protocol/handshake_machine_test.exs`
  passed 39 tests. Both later whole-suite commands include that correction.
- `git diff --check`: passed. No existing test was removed or weakened.

The 16 new public API tests execute full dual-endpoint handshakes, HRR,
all runtime-available suite/group combinations (three suites and three groups
on this runtime), paired read/write secrets, one-time actions, write-secret-before-
bytes ordering, single-byte fragmentation, same-level coalescing, wrong levels,
partial-message level changes, empty/missing/duplicate parameters, trust/identity
and CV/Finished failures, HRR immutable-field/repeat failures, no-common
algorithms/ALPN, declared and cumulative limits, configured certificate/extension
bounds, ignored legal PSK proposals/unknown modes, bounded NST, abort and terminal
calls. These are self-connection and negative tests, **not independent QUIC-TLS
interoperability evidence**. The existing raw-core fixture is separately checked.

## Fingerprint, independent-peer and boundary validation

- `mix format --check-formatted`: passed.
- `mix compile --warnings-as-errors`: passed.
- `mix test`: **423 passed** (20 properties, 403 tests), 177 integration tests
  excluded. Log: `/tmp/ex_ssl-quic-final-default.log`.
- `mix test test/ssl/quic_test.exs test/ssl/fingerprint_test.exs`: **26 passed**
  (1 property, 25 tests), including new bounded malformed-input, certificate,
  signature and cumulative-output limits, unoffered selections and RFC 9001
  error-domain checks. Expected red checks were run before their implementation;
  logs: `/tmp/ex_ssl-quic-boundaries-{red,green}.log`.
- The core drops its ephemeral private-key reference after derivation; the
  existing independent-fixture inspection check now also asserts this release.
- `QUIC_TLS_PYTHON=/tmp/ex_ssl-quic-reference-venv/bin/python mix run
  e2e/quic_tls/run.exs`: **13/13 passed**, repeated after final production changes.
  Log: `/tmp/ex_ssl-quic-final-independent.log`. Both roles, three suites,
  ECDSA/RSA identities, exact directional-secret digests, ALPN, parameters and
  completion match independent aioquic 1.2.0. The additional client-identity
  scenario checks CertificateRequest/CertificateVerify handling. Setup and pinned
  dependencies: [reference harness](../e2e/quic_tls/README.md).
- Fingerprints: official FoxIO JA4 worked example and independent Caddy JA3
  expected projection/digest pass; unknown IDs, GREASE, signature order, binary
  ALPN, q/t provenance and bytewise observation of an actual emitted ClientHello
  pass. [Definition/license](FINGERPRINTS.md).
- RFC 9846/9001 and their listed errata were reviewed; dispositions, error mapping
  and secret lifetimes are recorded in [QUIC_TLS_STANDARDS.md](QUIC_TLS_STANDARDS.md).

## Acceptance map

| Group | Evidence |
| --- | --- |
| A: TCP compatibility | Default suite, full integration runs below, existing golden/OTP/OpenSSL/TLS1.2/STARTTLS/mTLS/resumption scenarios retained; no tests deleted or weakened |
| B: framing/resources | QUIC bytewise/coalesced input, illegal level/type, cross-level partial, declared/inbound/outbound budget, certificate count/bytes, extension/signature limits, terminal/empty calls and arbitrary bounded-input property |
| C: handshake/authentication | Real dual-endpoint ECDHE/CV/Finished, HRR/CH2, no-common and unoffered selections, trust/identity/CV/Finished negatives; independent ECDSA/RSA/client-identity scenarios |
| D: boundary | Complementary local read/write secrets, one-time events, secret-before-output assertions, separate parameter versus identity authentication, redacted Inspect and released terminal references |
| E: fingerprints | Official/reference expected values, raw/hash, q/t, GREASE/unknown/order and emitted-byte fragmentation |
| F: independent QUIC-TLS | Pinned aioquic TLS Context in both roles, 13 scenarios; explicit separate CI workflow provided |

Full QUIC networking is out of scope and **not tested**. The new CI workflow has
not been dispatched; local execution is evidence only for the current runtime,
not all supported OS/OTP combinations. The implementation remains experimental,
without a production-security certification or an independent human audit.

## Final integration gate

`mix test --include integration` (seed 449482): **598/600 passed**, 2 failed:
previously evidenced input-ordering peer assertion and an intermittent lifecycle
supervisor-child-count assertion at `connection_lifecycle_test.exs:303`.
Log: `/tmp/ex_ssl-quic-final-integration.log`.
The lifecycle scenario's isolated cold-start command failed on both changed and
original HEAD trees at the earlier `:gen_tcp.accept` timeout; this is a different
symptom and does **not** prove the child-count failure is baseline. Running the
entire lifecycle module with seed 449482 passed **28/28 on both trees**.
Logs: `/tmp/ex_ssl-quic-lifecycle-{current,baseline}.log` and
`/tmp/ex_ssl-quic-lifecycle-{current,baseline}-module.log`.
Same-seed whole-suite recheck after those comparisons:

- Changed tree: **599/600 passed** (20 properties, 580 tests), with only the
  previously evidenced `input_ordering_regression_test.exs:325` failure.
  Lifecycle passed on this recheck. Log:
  `/tmp/ex_ssl-quic-final-integration-recheck.log`.
- Original HEAD: **568/571 passed** (19 properties, 552 tests), failing the same
  input-ordering scenario, the previously evidenced KeyUpdate/backpressure
  scenario, and `ResumptionBlockedWriteTest`'s blocked-write deadline assertion.
  Log: `/tmp/ex_ssl-quic-original-integration-recheck.log`.
- The transient child-count assertion did not recur; its specific cause is
  unconfirmed and it is not relabeled as a proven baseline failure. It remains
  recorded as an intermittent validation risk.
- `git diff --check` passed. No commit, push, release or version bump was made.

The requested public TLS/fingerprint implementation and independent harness are
present. The full integration gate remains **failed**, not silently converted to
passing by excluding the baseline test. Addressing the pre-existing runtime
backpressure/closure failures is separate work; no such test was modified here.


## Completion audit against the task sections

This audit uses the task's explicit distinction between preserving the existing
TCP support and fixing newly introduced regressions. Pre-existing failures are
reported, not excluded or repaired as unrelated work. A failed whole-suite run
is not represented as a passing gate.

| Task section | Authoritative implementation and verification |
| --- | --- |
| 1: scope | Only this repository changed; no runtime dependency added, QUIC packet layer, TCP server API, commit, push or version change |
| 2: baseline and sources | Original HEAD and pre-edit commands above; original-tree comparisons retained; standards/errata audit in `QUIC_TLS_STANDARDS.md` |
| 3: shared core | `HandshakeMachine` calls shared `ClientHandshake`; TCP `ServerFlightVerifier` adapts `HandshakeCore` into records; `SSL.QUIC` calls the same core without record wrapping; server uses shared derivation/signatures; existing TCP vectors/regressions run |
| 4: public contract | `SSL.QUIC` public types and five functions, caller-owned redacted state and ordered actions; `QUIC_TLS_INTERFACE.md` covers ownership, levels, reliable queue handoff, completion/authentication separation and errors |
| 5: QUIC constraints | Empty session ID/no records/no CCS, mandatory raw extension 57, configured/runtime capability separation, bounded buffers, no Initial or packet keys; public negative tests and parameter-placement audit |
| 6: real roles | Actual ECDHE, PKIX, role-bound CV and Finished, HRR/CH2; self-connection and independent aioquic secrets/identity checks; unsupported server mTLS/resumption/0-RTT explicitly documented |
| 7: fingerprints | `SSL.Fingerprint`, reused ClientOffer envelope, original IDs/order, explicit transport, emitted-byte/fragmentation tests, official JA4 and independent JA3 reference values plus license |
| 8: verification | Acceptance A-F map above; original TCP tests retained; offline defaults plus explicit pinned independent harness and CI workflow; complete QUIC networking expressly not claimed |
| 9: artifacts | README/AGENTS/architecture/design/PRD/plan/compatibility/CHANGELOG updated; ADR, interface, implementation, standards and fingerprint documents present |

The final audit added a public extension-placement test covering missing or
duplicate EncryptedExtensions parameters and forbidden parameters in ServerHello,
CertificateRequest, certificate entries and NewSessionTicket. It also found and
fixed malformed profile extension containers raising an Enumerable exception:
`nil`, integers, maps and improper lists now return a structured configuration
error. The regression test was observed red before this correction and green
afterward (`/tmp/ex_ssl-quic-config-{red,green}.log`).

The original lifecycle module was additionally run with
`--seed 449482 --repeat-until-failure 10`: the initial run and all ten repetitions
passed 28 tests each. This did not reproduce the earlier supervisor-count symptom
and is not asserted to establish its root cause. Log:
`/tmp/ex_ssl-quic-lifecycle-baseline-repeat.log`.

Final current-tree commands after the profile correction and placement tests:

| Command | Result |
| --- | --- |
| `mix format --check-formatted` | Passed |
| `mix compile --warnings-as-errors` | Passed |
| `mix test` | **425 passed**: 20 properties, 405 tests; 177 integration tests excluded |
| `mix test --include integration --seed 449482` | **601/602 passed**: only the original input-ordering closure assertion failed; lifecycle passed |
| `git diff --check` | Passed |

Logs: `/tmp/ex_ssl-quic-audit-final-default.log` and
`/tmp/ex_ssl-quic-audit-final-integration.log`. The independent 13-scenario
reference result above remains the executed interoperability evidence. The
last configuration-only correction does not change the valid configurations
used by that harness.

All requested implementation artifacts and requirement-specific evidence are
present. The existing TCP closure-test failure is explicitly left outside the
new-regression repair scope in task section 8A. Thus delivery of the requested
TLS/fingerprint boundary is complete, while the repository-wide integration
suite is **not green**. The transient lifecycle observation remains a documented
validation risk, not a resolved defect or a proven baseline defect.
