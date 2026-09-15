# TLS 1.3 client compatibility

`ex_ssl` provides an experimental OTP `:ssl`-compatible client API for the
implemented subset below. Passing the repository tests is not a security
certification, and OTP `:ssl` remains the recommended default.

## Public API

| Surface | Supported behavior |
| --- | --- |
| `SSL.connect/2,3,4` | Authenticated TLS 1.3 client connections and passive binary/raw STARTTLS upgrades. Connect succeeds only after CertificateVerify and Finished validation. |
| `SSL.send/2` | Valid iodata of any logical size supported by available caller memory. Data is traversed without flattening the entire write and protected in records of at most 16,384 plaintext bytes. One logical write is admitted at a time; another caller receives `{:error, :busy}`. There is no automatic replay. |
| `SSL.recv/2,3` | Passive raw binary receive. Length zero returns available plaintext; a positive length waits for exactly that many bytes. One passive receive is admitted, and the maximum requested/buffered plaintext is 1 MiB. |
| `SSL.setopts/2` | Atomic support for `active: false | :once`, `send_timeout`, and `send_timeout_close: true`. Unknown, duplicate, malformed, or unsupported options reject the whole request. |
| `SSL.controlling_process/2` | Transfers the application owner and monitor. The connection process remains the TCP owner and sole owner of TLS state. Only the current application owner may transfer. |
| `SSL.negotiated_protocol/1` | Returns authenticated ALPN as `{:ok, binary}` or `{:error, :protocol_not_negotiated}`. |
| `SSL.close/1` | Idempotent local close. Sends close_notify when no application write is uncertain and wakes admitted calls. |

Closed and invalid handles follow the existing public call mapping. An orderly
TLS closure produces `:closed`; abrupt TCP loss or unexpected connection-process
loss produces `:econnreset`. TLS failures use redacted `{:tls_alert, ...}`
reasons. Other roadmap APIs are not exported as success-returning stubs.

## Ownership and active-once behavior

The public socket term is stable for the life of a connection. Ownership
transfer changes only future application delivery and owner-death monitoring;
it does not move TCP ownership, traffic keys, sequence counters, buffers, or
replies already assigned to admitted `send`/`recv` callers.

A self-transfer succeeds. A non-owner receives `{:error, :not_owner}`. A target
known to be dead before the transfer receives `{:error, :noproc}` without
changing the live connection. If the target dies after the transfer is
committed, the successful transfer stands and its `DOWN` closes the connection.
This deliberate pre-check differs from OTP versions that can return `:ok` for an
already-dead target and then asynchronously close. A stale `DOWN` from an old
owner is ignored after a successful monitor replacement.

Messages already sent to the old owner's mailbox stay there; mailbox contents
cannot be migrated by changing a monitor. The caller must transfer a passive
socket before activating it when it requires a clean mailbox handoff.

Application `active: :once` is independent of the raw TCP socket's internal
active-once processing. One activation permits at most one
`{:ssl, socket, binary}` message and then becomes application-passive. It emits
no `{:ssl_passive, socket}` notification. Rearming drains already-buffered
plaintext immediately. An explicit `active: false` stops future data messages
without retracting messages already delivered or dropping buffered bytes.

An activation request while a passive `recv` is admitted returns
`{:error, :einval}` and leaves that receive and all bytes untouched. Graceful
and abrupt terminal events are delivered once as `{:ssl_closed, socket}` or
`{:ssl_error, socket, reason}` for an active-once subscription, after earlier
deliverable plaintext. Handshake traffic, NewSessionTicket, and KeyUpdate never
consume application delivery credit.

## Connection options

Supported connection options are:

- `:binary` or `mode: :binary`;
- `packet: :raw | 0`;
- `active: false | :once` (default `false`);
- `verify: :verify_peer`;
- `cacerts` or `cacertfile`;
- DNS `server_name_indication`;
- `customize_hostname_check: [match_fun: fun]`;
- `versions: [:"tlsv1.3"]`;
- non-negative integer `depth` (default `10`);
- non-negative integer or `:infinity` `send_timeout` (default 5,000 ms);
- `send_timeout_close: true`;
- `alpn_advertised_protocols: [nonempty_binary, ...]`;
- `ex_ssl: [profile: :default | %SSL.ClientHello.WireProfile{}]`.

Verification cannot be disabled. TLS 1.2 and mixed TLS 1.3/TLS 1.2 version
lists are rejected. Packet modes, list mode, active true/active-N, arbitrary TCP
options, client certificates, and `send_timeout_close: false` remain
unsupported. Unsupported or malformed options return a redacted
`{:error, {:options, reason}}`; supplied option data is not echoed.

`depth` is passed to OTP `:public_key` path validation as the maximum number of
intermediate CA certificates. It is independent of the TLS Certificate-message
count and the separate certificate count/byte resource limits. Differential
tests cover direct root-signed and one-intermediate paths at both boundaries.

## ALPN and WireProfile precedence

- The default profile incorporates a top-level ALPN list in its declared order.
- An explicit profile with no top-level ALPN is emitted unchanged.
- An explicit profile plus top-level ALPN requires an exact ordered match.
- A profile without ALPN never silently gains ALPN.
- No ALPN option preserves the existing profile and does not inject HTTP
  protocols into non-HTTP connections.

The server selection is validated as exactly one protocol offered by the
materialized ClientHello. It is retained only after authenticated handshake
validation and is never inferred from the first advertisement.

## Send deadlines, ordering, and cleanup

Each admitted write captures the current `send_timeout` and creates one
monotonic deadline for the whole logical write. Record fragmentation does not
restart that deadline. `SSL.setopts/2` changes the timeout for the next admitted
write; it does not change a write that already holds admission.

A persistent connection-owned writer performs at most one bounded ciphertext
send at a time. The connection process remains authoritative for encryption,
epochs, record order, and admission. It processes deferred inbound TLS traffic
between completed writes/records, so KeyUpdate responses and alerts cannot race
ahead of an uncertain socket send. Timeout or sender death after transmission
starts fails the connection closed; uncertain application bytes are never
retried. Close and owner death remain responsive even with an infinite send
timeout, and all monitors, timers, cursors, and writer processes are cleaned up.

## STARTTLS and security boundaries

STARTTLS callers must own a connected binary/passive/raw `:gen_tcp` socket,
fully consume and validate the positive upgrade reply, reject plaintext held in
their own parser, and supply a DNS reference identity through
`server_name_indication`. Queued or delivered TCP plaintext causes explicit
failure and owned-socket closure. A non-owner's TCP socket is not closed.

Profiles affect offered wire capabilities only. They cannot replace trust or
identity verification. Record, handshake, certificate, trust-store, and passive
plaintext bounds remain independently enforced. No traffic secrets, private
keys, or application payloads are exposed through public metadata or ordinary
inspection.

## Remaining limitations

TLS 1.2, server TLS, DTLS, QUIC/HTTP/3, client authentication, resumption,
0-RTT, post-handshake authentication, active true/active-N, packet framing,
exporters, and full OTP API parity are out of scope. ALPN negotiation alone is
not evidence of an HTTP/2 request. See
[HTTP_FETCH_INTEGRATION.md](HTTP_FETCH_INTEGRATION.md) for the separate consumer
work still required.
