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

The foundation does not include ClientHello serialization, a complete HRR flow, TLS
connectivity, or OTP socket compatibility.

## Next assignment

Implement deterministic ClientHello generation plus ServerHello/HelloRetryRequest
parsing. The bounded scope is the required parts of Phase 3 Tasks 3A-3D plus
Phase 4A in `IMPLEMENTATION_PLAN.md`, not all of Phase 3 or Phase 4.

Required order and dependencies:

1. First implement the missing Phase 2D dependency, `SSL.Crypto.KeyExchange`, for
   X25519 and secp256r1 using OTP `:crypto` with runtime capability checks. Test
   successful agreement and malformed peer keys.
2. Implement the typed extension encoding, GREASE materialization, ordered
   ClientHello AST, and exact serializer required by this assignment:
   profile validation -> materialization -> ordered AST -> exact bytes.
3. Generate fresh per-connection randomness and ephemeral private/public KeyShare
   material. Deterministic injection is allowed only at the test boundary and must
   not weaken production freshness; profiles must never contain reusable real key
   material.
4. Perform final wire-size validation after materialization, including SNI and
   deferred PSK data whose current structural checks use placeholder lengths.
5. Add length-bounded ServerHello/HRR parsing with semantic validation for the
   selected TLS version, cipher suite, key share, and allowed extensions.
6. Add exact deterministic golden-wire fixtures plus negative and fragmentation
   tests for the new encoders, serializer, parser, semantic checks, and malformed
   key-exchange inputs.

Do not include the Phase 3E ClientHello parser or Phase 3F JA3/JA4 analyzers unless
the bounded implementation proves one is strictly required; golden ClientHello
tests should compare exact serialized bytes directly. Do not implement AEAD, the
TLS 1.3 key schedule, encrypted-handshake processing, or connection orchestration
in this assignment.

This assignment must not claim full HRR support: transcript rewrite exists, but the
complete HRR transition, fresh second KeyShare, and ClientHello2 generation are
later work. Parsing HRR is not the full transition. It also must not claim TLS
connectivity or OTP socket compatibility.

Constraints:

- runtime code must not use `:ssl` to perform TLS;
- tests may use OTP `:ssl` as reference/interoperability endpoint;
- use RFC 9846 as the TLS 1.3 source of truth;
- use `:crypto`/`:public_key` for primitives;
- preserve protocol byte order with ordered structures;
- keep wire parsing pure and length-bounded;
- do not add a NIF;
- do not claim full OTP compatibility yet.

Before coding, inspect the running OTP version and verify any exact `:crypto` API calls against its documentation/runtime capability.
