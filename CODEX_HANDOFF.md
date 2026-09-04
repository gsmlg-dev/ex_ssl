# Codex Handoff — ex_ssl

You are starting a new Elixir/OTP library named `ex_ssl`.

Read in order:

1. `AGENTS.md` — non-negotiable implementation rules
2. `PRD.md` — required product behavior and scope
3. `ARCHITECTURE.md` — system boundaries and state ownership
4. `DESIGN.md` — concrete APIs/data models/algorithms
5. `IMPLEMENTATION_PLAN.md` — phased execution plan
6. `README.md` — user-facing positioning

## Immediate assignment

Implement **Phase 0 + the foundation subset defined in “Definition of done for Codex initial assignment” in `IMPLEMENTATION_PLAN.md`**.

Do not implement the whole TLS connection in one pass.

The first PR should establish:

- Mix/OTP app `:ex_ssl`;
- public module `SSL`;
- supervision skeleton;
- TLS record stream framing;
- TLS handshake stream framing;
- transcript handling including HelloRetryRequest rewrite tests;
- TLS 1.3 HKDF/Expand-Label tests;
- traffic nonce helper/tests;
- initial `WireProfile` model/validation skeleton;
- compatibility test harness skeleton;
- CI/test foundation.

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

