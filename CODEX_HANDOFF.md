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

This milestone does not include the Phase 3F JA3/JA4 analyzers, TLS connectivity,
OTP socket compatibility, a connection state machine, or the Phase 4B HRR
transition. In particular, HRR parsing and transcript support do not provide full
HRR support: fresh second KeyShare and ClientHello2 generation remain future work.

## Pure authenticated-flight milestone

The normal, certificate-authenticated in-memory server-flight path is complete for
the implemented subset. It derives handshake/application traffic secrets, protects
TLS 1.3 records, verifies EncryptedExtensions, Certificate, CertificateVerify, and
Finished, retains exact transcript bytes, and produces the client Finished record.

Security repairs bind negotiation to the exact ClientHello and reparsed ServerHello,
keep transcript and signature hashes independent, enforce TLSInnerPlaintext and
TLSCiphertext limits with specific fatal alerts, reject non-PSK early data, validate
ALPN and CertificateEntry response extensions against the byte-derived offer, and
require DNS/IP SAN service identities without CN fallback.

Evidence includes fixed known-answer primitive vectors and reproducible constructed
full flights using disposable test-only certificates, fixed RFC 7748 X25519 scalars,
SHA-384 transcripts, and both ECDSA-SHA256 and RSA-PSS-RSAE-SHA256 signatures. These
constructed vectors are not represented as live OpenSSL captures.

## Next assignment

Proceed to Phase 5 connection orchestration only after the repaired pure suite and
both documented CI runtime matrices remain green. `SSL.connect`, socket ownership,
active/passive delivery, complete HRR, resumption, and 0-RTT remain future work.
