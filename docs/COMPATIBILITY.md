# TLS client compatibility and Manifold acceptance contract

This is an experimental OTP `:ssl`-compatible client API for the implemented
feature subset. Passing tests is not a security certification. OTP remains the
default backend. No release, merge, or production configuration change is part
of this milestone.

## Revisions and consumer inventory

Implementation starts at ex_ssl `04180a504c55c65d4f339d459e011e2e2307bc49`.
The consumer audit covers Manifold `c21ea5d4e41b367bf2fa0b94dea54552cfa60af6`.
Manifold's `docs/DESIGN.md` is its architecture/product document; it has no
separate `ARCHITECTURE.md` or `PRD.md` at that revision.

| Consumer | Actual calls/options | Acceptance gate |
| --- | --- | --- |
| IMAP | `imap/client.ex`: host `:ssl.connect/4`, socket upgrade `connect/3`, `send/2`, `recv(socket, 0, 30_000)`, `close/1`. Options: `:binary`, `active: false`, `packet: :raw`, `verify: :verify_peer`, `cacerts: :public_key.cacerts_get()`, charlist SNI, `customize_hostname_check: [match_fun: :public_key.pkix_verify_hostname_match_fun(:https)]`. | Authenticate, select mailbox, fetch literal/message and logout over direct TLS and STARTTLS; reject certificate/transport failures. |
| SMTP submission | `smtp/client.ex`: same four operations and trust options; connect timeout 15 seconds; receive uses the remaining monotonic reply deadline. STARTTLS follows greeting/EHLO/220 and re-EHLO after upgrade. | Authenticate and submit to local recipients over direct TLS and STARTTLS. Preserve definite versus uncertain DATA outcomes and never replay automatically. |
| EAS | `eas/client.ex` calls `Req.request/1`: receive timeout 60 seconds, connect timeout 15 seconds, HTTP/1 only, decoded body, compression disabled, plus request options. Supports OPTIONS/POST, query, Basic auth, cookies and binary WBXML. Locked Req 0.7.3 → Finch 0.23.0 → Mint 1.9.3. | Explicit HTTP adapter using SSL, verified server-observed ClientHello, binary exchanges and response framing. Req's `adapter` is an extension point; `connect_options.transport_opts` alone cannot replace Mint's hardwired OTP TLS transport. |
| Unchanged | Inbound `gen_smtp` TLS, Phoenix/server TLS, database TLS, cloud HTTP, Gmail/Microsoft Graph HTTP, Resend and other unrelated Req consumers. | No backend or production configuration changes. |

The paths above are under Manifold's
`apps/manifold_connectors/lib/manifold/connectors/`. Source options, locks and
dependency implementations were inspected, including Req's adapter boundary,
Finch's `Mint.HTTP.connect` call and `Mint.Core.Transport.SSL`.

## Public library subset

| Surface | Status / restriction |
| --- | --- |
| `SSL.connect(host, port, opts, timeout)` and `/3` | TLS 1.3 client; `/3` defaults timeout to infinity. DNS routing and reference identity remain separate when connecting to an IP with DNS SNI. |
| `SSL.connect(tcp_socket, opts, timeout)` and `/2` | Required STARTTLS upgrade; ownership and plaintext boundary requirements below. `/2` defaults timeout to infinity. |
| `SSL.send/2` | Accepts iodata. Splits application writes into at most 16,384-byte TLS records. At most one write is admitted; concurrent writes return `{:error, :busy}`. Maximum one call is 1 MiB (`:emsgsize` above the limit). No automatic retries. |
| `SSL.recv/3` and `/2` | Passive binary/raw only. Zero length returns available application bytes. Positive length waits for exactly that many bytes (maximum 1 MiB). Surplus/partial bytes persist. `/2` uses infinity. |
| Receive deadlines | Non-negative milliseconds or `:infinity`; invalid values return `:badarg`. Zero polls. Fragments do not extend the monotonic deadline. A timeout retains buffered plaintext; a dead receiver is cancelled. |
| Concurrent receives | One pending receiver; a competing receive returns `{:error, :einval}`. This is an explicit restriction: OTP reference behavior for concurrent calls is not emulated. |
| `SSL.close/1` | Sends close_notify when possible and closes. Idempotent for a previously closed handle; pending calls wake with `:closed`. |
| Closed sockets | Authenticated peer close_notify preserves previously decrypted bytes for subsequent reads, then returns `{:error, :closed}`. Local close and owner shutdown also leave a `:closed` handle. Abrupt TCP loss or unexpected connection-process death returns `{:error, :econnreset}`, including later calls after process exit; undelivered bytes are discarded on transport failure. TLS authentication/protocol errors return a redacted `{:tls_alert, {category, description}}`. |
| Other OTP API | Not exported. No success-returning compatibility stubs. |

Supported options are `:binary` or `mode: :binary`, `active: false`,
`packet: :raw` or `0`, `verify: :verify_peer`, `cacerts` (DER or actual OTP
`cacerts_get` entries), `cacertfile`, DNS `server_name_indication`,
`customize_hostname_check: [match_fun: fun]`, `versions: [:"tlsv1.3"]`, and
`ex_ssl: [profile: :default | %SSL.ClientHello.WireProfile{}]`.
The profile only changes offered wire capabilities. It does not replace trust or
reference identity. Unsupported, malformed and duplicate options are rejected
with `{:error, {:options, reason}}`; error values are redacted rather than echoing
arbitrary option data. Trust defaults to the system CA bundle. Verification
cannot be disabled. Named profile registries are not implemented.

## STARTTLS caller contract

Before calling `SSL.connect(tcp_socket, ...)`, the caller must:

1. Own a connected `:gen_tcp` port socket configured binary/passive/raw.
2. Fully consume and validate the application protocol's positive upgrade reply.
3. Reject unexpected data in the application's own parser buffer; SSL cannot
   inspect a buffer held by its caller.
4. Supply the DNS reference identity as `server_name_indication`.

The upgrade checks socket state, already-delivered TCP messages and queued TCP
bytes before transferring ownership. Delivered messages are not silently removed.
Unexpected queued bytes cause `:pending_plaintext` and connection closure.
Validation/timeout/handoff/handshake failure closes an owned socket. A non-owner
gets `:not_owner` without closing another process's socket. Never resume plaintext
after any failed upgrade. Alternative `inet_backend: :socket` handles are not
supported in this subset.

## Resource and authentication boundaries

One temporary `SSL.Connection` owns each TCP socket, all traffic epochs and
sequence numbers, parser buffers, operations and application-owner monitor.
Internal active-once delivery continues protocol processing independently of the
public passive mode. Plaintext buffering is bounded to 1 MiB; rearming pauses
near the limit. A single admitted write is bounded to 1 MiB, and socket send
backpressure has a five-second send timeout. A timed-out write closes the session.

Record limits are 16,384 bytes for plaintext and 16,640 for ciphertext; handshake
messages are limited to 1 MiB. Certificate messages allow at most 16 certificates,
256 KiB per certificate and 1 MiB total DER. Trust-store normalization has a separate 4,096-anchor
limit. The opaque public socket contains a process identifier, connection reference,
and an atomic terminal-status cell holding no TLS or application data. This cell
preserves the distinction between authenticated closure and transport failure
without retaining a connection process after it exits.
Inspect/status/crash formatting redacts secret state and application payloads;
ordinary logging and key logging are disabled. BEAM cannot guarantee deterministic
memory zeroization.

RSA-PSS with RSAE keys and SHA-256/384/512, and ECDSA P-256/SHA-256 authenticate
servers. TLS AES-128-GCM, AES-256-GCM and ChaCha20-Poly1305 and X25519/P-256 are
the supported cryptographic algorithms where available from OTP crypto.
HRR uses the transcript message_hash rewrite. Optional handshake
CertificateRequest receives an empty client Certificate; client authentication
is not supported. Peer KeyUpdate rotates independent traffic epochs and sends
any required response before subsequent application traffic. NewSessionTicket
is validated then discarded. Other post-handshake messages fail explicitly.

## Evidence and staged readiness

| Layer | Evidence / gate |
| --- | --- |
| Pure protocol/crypto/PKIX/profile components | Existing deterministic vectors, negative authentication tests, framing properties and wire checks; new incremental/HRR/post-handshake regressions. |
| Public API | Local lifecycle suite covers buffering, partial timeouts, cancellation, owner death, concurrent close, limits and upgrade failure cleanup. |
| Independent interoperability | Mandatory local OTP and OpenSSL peers with generated certificates; dedicated `.github/workflows/interop.yml` job. Exact validation results are recorded after completion below. |
| Caddy fingerprints | Existing dedicated e2e workflow uses a thin public SSL API wrapper. Live Caddy execution stays in CI per `e2e/README.md`; local compile does not claim live fingerprint validation. |
| IMAP integration | Pending library gate and separate consumer change. |
| SMTP submission integration | Pending library gate and separate consumer change. |
| EAS integration | Pending library gate and separate verified HTTP adapter. |

Deliberate exclusions: TLS 1.2 and downgrade fallback, server TLS, DTLS, QUIC,
HTTP/2, client certificate authentication, post-handshake authentication,
session resumption, 0-RTT, active application modes, packet modes beyond raw,
exporters and general OTP parity. HTTP/EAS framing belongs in Manifold.

### Library gate executed on 2026-09-14

- OTP 28.5.0.5 / Elixir 1.18.5 and OTP 29.0.6 / Elixir 1.20.4:
  `mix test --include integration` — 278 tests and 15 properties passed,
  with no skipped interoperability tests. Local OTP/OpenSSL peers generate
  certificates at test time; no production endpoint or account is required.
- `mix format --check-formatted`, `mix compile --warnings-as-errors`, and
  `MIX_ENV=test mix compile --warnings-as-errors` passed on both toolchains.
  `MIX_ENV=prod mix compile --warnings-as-errors` also passed locally.
- `cd e2e && mix format --check-formatted && mix compile --warnings-as-errors`
  passed on OTP 29. Live Caddy execution was not run locally, as required by
  the existing e2e workflow policy. CI has not yet been executed for this branch.
- OTP 29 validation used the Docker image
  `hexpm/elixir:1.20.4-erlang-29.0.6-ubuntu-noble-20260905`, with OpenSSL,
  CA certificates and `libsctp1` installed, a read-only source mount and a
  separate `/tmp/ex_ssl_build` build directory.

The library gate permits consumer implementation and controlled local testing.
It does not establish readiness of any Manifold consumer until that consumer's
separate workflow tests pass.
