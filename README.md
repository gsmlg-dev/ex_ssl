# ex_ssl

`ex_ssl` is an experimental TLS implementation for Elixir/OTP with two primary goals:

1. provide a client API that is behaviorally compatible with Erlang/OTP `:ssl` where implemented;
2. provide programmable TLS ClientHello wire profiles for applications that need precise control over observable TLS handshake behavior.

The OTP application is `:ex_ssl`. The public compatibility module is `SSL` (`Elixir.SSL`), which does not conflict with Erlang's built-in `:ssl` module.

> **Status:** architecture / initial implementation. Do not treat `ex_ssl` as a production replacement for OTP `:ssl` until the compatibility and security milestones documented in this repository are complete.

## Why ex_ssl?

OTP `:ssl` is the correct default TLS implementation for normal Erlang/Elixir applications. `ex_ssl` exists for cases where an application also needs deterministic or profile-driven control of the ClientHello wire representation, including characteristics such as:

- cipher-suite ordering;
- extension ordering;
- supported versions/groups;
- KeyShare shape and placement;
- signature algorithm ordering;
- ALPN ordering;
- GREASE placement/policy;
- legacy session-id/compatibility behavior;
- padding and selected record-shaping behavior.

The library treats these as a **wire profile**, not as a JA3 configuration. JA3 and JA4 are derived fingerprints of the emitted/parsed ClientHello.

## Naming

```text
Package / repository: ex_ssl
OTP application:      :ex_ssl
Public API:            SSL
Internal namespace:    SSL.*
```

Migration is intended to look like:

```elixir
# OTP
:ssl.connect(host, port, options)

# ex_ssl
SSL.connect(host, port, options)
```

Custom behavior is additive and namespaced:

```elixir
SSL.connect(host, port,
  verify: :verify_peer,
  server_name_indication: host,
  ex_ssl: [
    profile: :my_wire_profile
  ]
)
```

## Compatibility target

The initial compatibility baseline is the Erlang/OTP 29 `:ssl` client API.

Planned/targeted client functions include:

```text
connect/2,3,4
send/2
recv/2,3
close/1,2
shutdown/2
setopts/2
getopts/2
controlling_process/2
peername/1
sockname/1
peercert/1
negotiated_protocol/1
connection_information/1,2
getstat/1,2
update_keys/2
export_key_materials/4,5
format_error/1
versions/0
```

Compatibility means observable behavior, not only matching names and arities.

For implemented features, `ex_ssl` aims to match:

- success/error tuple forms;
- timeout semantics;
- active/passive socket semantics;
- controlling-process behavior;
- standard TLS/socket option behavior;
- STARTTLS-style upgrade of an existing TCP socket;
- active message forms.

The active message contract targets OTP forms:

```elixir
{:ssl, socket, data}
{:ssl_closed, socket}
{:ssl_error, socket, reason}
{:ssl_passive, socket}
```

## Protocol scope

The first protocol target is **TLS 1.3 client only**, using RFC 9846 as the normative specification.

Initial target features:

- TLS 1.3 ClientHello/ServerHello;
- HelloRetryRequest;
- EncryptedExtensions;
- server Certificate / CertificateVerify / Finished;
- client Finished;
- X.509 path and service-identity verification;
- ALPN;
- TLS alerts and close_notify;
- NewSessionTicket parsing;
- KeyUpdate;
- passive and OTP-style active receive modes;
- STARTTLS upgrade;
- programmable ClientHello WireProfile;
- GREASE (RFC 8701);
- JA3 and JA4 introspection.

Initial target cipher suites:

```text
TLS_AES_128_GCM_SHA256
TLS_AES_256_GCM_SHA384
TLS_CHACHA20_POLY1305_SHA256
```

Initial target groups:

```text
X25519
secp256r1
```

Runtime support depends on the crypto provider available to OTP.

## Architecture

```text
Application
    │
    ▼
   SSL                     OTP-compatible facade
    │
    ▼
SSL.Connection             :gen_statem per connection
    │
    ├── SSL.Protocol.*     records / handshake / transcript
    ├── SSL.Crypto.*       HKDF / AEAD / key schedule / ECDHE
    ├── SSL.PKIX.*         certificate + identity verification
    ├── SSL.ClientHello.*  WireProfile / GREASE / serializer
    ├── SSL.Fingerprint.*  JA3 / JA4 / wire inspection
    └── SSL.Packet         application packet modes
    │
    ▼
:gen_tcp
```

The raw TCP socket is controlled by `SSL.Connection`, normally using internal `active: :once`. Application-visible `active` mode is implemented above TLS so handshake/record processing cannot be disabled by application socket mode.

## Wire profiles

The profile is the source of truth for what `ex_ssl` attempts to emit.

Conceptually:

```text
WireProfile
  │
  ▼
validate against TLS/runtime capabilities
  │
  ▼
materialize per-connection randomness, GREASE and fresh KeyShare
  │
  ▼
ordered ClientHello AST
  │
  ├──► JA3
  ├──► JA4
  └──► exact-wire inspection
  │
  ▼
serialize
```

Profiles may describe KeyShare group/order/position but may **not** reuse actual ephemeral private/public key material between real connections.

## Important limitations

### Not a complete device impersonation layer

A matching TLS ClientHello does not guarantee that a remote service will see a client as identical to a browser or mobile application. Other observable layers can include TCP/IP behavior, HTTP/2 SETTINGS and framing, header behavior, QUIC/HTTP/3 behavior, application protocol details, and timing.

`ex_ssl` focuses on the TLS layer.

### TLS 1.2 comes later

Many real clients advertise both TLS 1.3 and TLS 1.2. A profile must not normally advertise a protocol version that `ex_ssl` cannot negotiate. TLS 1.2 client support is therefore a planned follow-up required for broader faithful profile coverage.

### BEAM secret zeroization

Elixir/Erlang immutable binaries and garbage collection do not provide deterministic memory zeroization. `ex_ssl` minimizes secret lifetime and scope but does not claim guaranteed erasure of every in-memory copy.

## Security model

Fingerprint fidelity never overrides TLS authentication.

`ex_ssl` must fail closed for:

- invalid certificate chains;
- service identity mismatch;
- invalid CertificateVerify signatures;
- invalid Finished values;
- AEAD authentication failures;
- invalid protocol state;
- record/sequence limit violations.

The implementation uses OTP `:crypto` and `:public_key` for cryptographic primitives and X.509 functionality rather than reimplementing those primitives in Elixir.

## Development status

Development is organized into staged gates:

1. stream framing + transcript + HKDF;
2. WireProfile + deterministic ClientHello;
3. ServerHello/HRR + server-flight verification;
4. first authenticated TLS 1.3 connection;
5. application data;
6. OTP active/passive compatibility;
7. STARTTLS;
8. broader OTP API/options;
9. KeyUpdate/exporters/resumption;
10. verified real-world profiles and hardening.

See:

- [ARCHITECTURE.md](ARCHITECTURE.md)
- [DESIGN.md](DESIGN.md)
- [PRD.md](PRD.md)
- [IMPLEMENTATION_PLAN.md](IMPLEMENTATION_PLAN.md)
- [AGENTS.md](AGENTS.md)

## Testing philosophy

The project uses four complementary test classes:

### Protocol/vector tests

Cryptographic and transcript operations are checked against independent known results.

### Property/fragmentation tests

Parsers are tested across arbitrary TCP, record, and handshake fragmentation boundaries.

### Interoperability tests

`ex_ssl` connects to independent TLS implementations such as OTP `:ssl` and OpenSSL.

### Differential compatibility tests

Equivalent socket/API scenarios are run against `:ssl` and `SSL`, comparing externally visible behavior.

A compatibility claim is not complete until covered by tests.

## Standards and references

Primary references:

- TLS 1.3: RFC 9846 — https://www.rfc-editor.org/info/rfc9846/
- GREASE: RFC 8701 — https://www.rfc-editor.org/info/rfc8701/
- TLS service identity: RFC 9525 — https://www.rfc-editor.org/info/rfc9525/
- Erlang/OTP `:ssl`: https://www.erlang.org/doc/apps/ssl/ssl.html
- Erlang/OTP `:crypto`: https://www.erlang.org/doc/apps/crypto/crypto.html
- Erlang/OTP `:public_key`: https://www.erlang.org/doc/apps/public_key/public_key.html
- JA4 technical details: https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/JA4.md

## License

TBD before public release.

