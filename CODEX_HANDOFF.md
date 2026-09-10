# Codex Handoff — ex_ssl

You are starting a new Elixir/OTP library named `ex_ssl`.

Read in order:

1. `AGENTS.md` — non-negotiable implementation rules
2. `PRD.md` — required product behavior and scope
3. `ARCHITECTURE.md` — system boundaries and state ownership
4. `DESIGN.md` — concrete APIs/data models/algorithms
5. `IMPLEMENTATION_PLAN.md` — phased execution plan
6. `README.md` — user-facing positioning

## Foundation status

The foundation assignment defined in “Definition of done for Codex initial assignment”
in `IMPLEMENTATION_PLAN.md` is complete. It includes the Mix/OTP application and
supervision skeleton, the documented `SSL` facade, bounded record and handshake
framers, transcript checkpoints and HRR `message_hash` rewrite, HKDF/Expand-Label
and traffic nonce primitives, initial `WireProfile` validation, fragmentation/vector/
property tests, the compatibility-harness skeleton, and CI coverage for the documented
runtime tuples.

The foundation does not include a complete HRR flow, TLS connectivity, or OTP
socket compatibility. The subsequent deterministic ClientHello and
ServerHello/HelloRetryRequest parsing milestone is recorded below.

## Completed milestone

The deterministic ClientHello and ServerHello/HelloRetryRequest parsing assignment
is complete for the required parts of Phase 3 Tasks 3A-3D and Phase 4A in
`IMPLEMENTATION_PLAN.md`. It includes fresh X25519/secp256r1 key exchange material,
profile-driven materialization, exact ordered ClientHello serialization, final
materialized-length checks, and pure bounded ServerHello/HRR parsing with semantic,
negative, fragmentation, and golden-wire tests.

This milestone does not include the Phase 3E ClientHello parser, Phase 3F JA3/JA4
analyzers, TLS connectivity, OTP socket compatibility, a connection state machine,
authenticated handshake verification, or the Phase 4B HRR transition. In particular,
HRR parsing and transcript support do not provide full HRR support: fresh second
KeyShare and ClientHello2 generation remain future work.

## Next assignment

Implement the pure prerequisites for the first authenticated TLS 1.3 handshake,
following Phase 2C/2E and Phase 4B-4F of `IMPLEMENTATION_PLAN.md` before Phase 5
connection orchestration. Keep the work bounded to an in-memory handshake path;
do not add `SSL.connect`, socket modes, or OTP compatibility claims in this step.

Required dependencies and acceptance requirements:

1. Complete the TLS 1.3 key schedule beyond the existing HKDF helpers, including
   handshake/application traffic secrets, Finished keys, and the derivations needed
   for the selected cipher suites.
2. Implement AEAD TLS record protection with independent sequence state, encrypted
   handshake codecs, and exact transcript-byte handling. Enforce record/message
   limits and return structured protocol errors for malformed input and authentication
   failures.
3. Implement server-flight verification for EncryptedExtensions, Certificate,
   CertificateVerify, and Finished, using `:public_key` for PKIX chain and hostname
   validation, constant-time Finished comparison, and standard signature verification.
   Define alert/error behavior
   for invalid certificates, identities, signatures, Finished values, and AEAD tags.
4. Keep fresh per-connection key material and the no-runtime-`:ssl` rule. Preserve
   ordered wire bytes and add deterministic vectors, captured-flight fixtures, and
   negative/fragmentation tests, including malformed certificates and cryptographic
   failures.
5. If the first in-memory flow requires HRR, implement Phase 4B validation, transcript
   rewrite, fresh second KeyShare, and profile-preserving ClientHello2; otherwise keep
   the HRR transition explicitly deferred and test the normal ServerHello path first.
6. Add independent interoperability evidence against OTP `:ssl` and OpenSSL once
   the pure verification path is stable; do not treat ex_ssl-to-ex_ssl tests as
   interoperability.

The exit gate is a pure/in-memory captured server flight that verifies correctly,
with exact transcript bytes, bounded parsing, negative vectors, and documented
failure/alert behavior. Connection orchestration and live socket compatibility
remain the subsequent Phase 5 assignment.
