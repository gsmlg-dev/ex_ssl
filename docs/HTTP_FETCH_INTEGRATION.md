# http_fetch opt-in transport integration

This guide records the library contract audited against `gsmlg-dev/http_fetch`
revision `540225cec69cd2c1e41eb80b956fd6f1a8df7b70`. The ex_ssl fixture proves
the transport lifecycle below; it does not claim that `HTTP.fetch` already uses
ex_ssl.

## Audited consumer contract

The relevant consumer entry points are:

- `apps/http_core/lib/http/transport.ex`: the transport callbacks `connect/4`,
  `controlling_process/2`, `send/2`, `setopts/2`, `close/1`, and
  `normalize_message/2`;
- `apps/http_core/lib/http/transport/ssl.ex`: OTP implementation, trust defaults,
  depth, active message normalization, and ALPN lookup;
- `apps/http_fetch/lib/http/socket_client.ex`: `connect_in_worker/7`,
  `transfer_connected_socket/5`, task-based `send_request/4`,
  `activate_socket/2`, and protocol selection;
- `apps/http_fetch/lib/http/fetch_options.ex`: public transport option
  conversion;
- `apps/http_web_socket/lib/http/web_socket/connection.ex`: passive HTTP Upgrade
  receive followed by active-once WebSocket delivery.

`HTTP.SocketClient` connects in a short-lived worker with `active: false`, sends
the socket handle to the long-lived request process, waits for authorization,
calls `controlling_process/2`, and exits. Separate supervised tasks call
`send/2`. The request process selects a protocol from authenticated ALPN and
repeatedly calls `setopts(active: :once)` while processing response bytes.

The fixture in `test/ssl/http_fetch_transport_contract_test.exs` reproduces
that ownership/send/ALPN/active-once/abort pattern against a generated local OTP
TLS peer. It is transport-contract evidence only.

## ex_ssl adapter rules

An opt-in adapter may call these implemented functions directly:

```elixir
SSL.connect(host, port, tls_options, connect_timeout)
SSL.controlling_process(socket, owner)
SSL.send(socket, iodata)
SSL.setopts(socket, active: :once)
SSL.negotiated_protocol(socket)
SSL.recv(socket, length, timeout)
SSL.close(socket)
```

It must normalize active messages exactly as the OTP adapter does:

```elixir
{:ssl, socket, data}          -> {:data, data}
{:ssl_closed, socket}         -> :closed
{:ssl_error, socket, reason}  -> {:error, reason}
```

Map `{:error, :protocol_not_negotiated}` to the consumer's `nil` ALPN result.
Keep protocol choice in http_fetch: `h2` selects HTTP/2; an absent or
`http/1.1` selection follows the requested HTTP mode. ex_ssl does not implement
HTTP framing.

Use the exact TLS version list `versions: [:"tlsv1.3"]`. The current OTP adapter
defaults to `[:"tlsv1.3", :"tlsv1.2"]`, which ex_ssl correctly rejects rather
than silently advertising unsupported TLS 1.2. Preserve `depth: 4`, peer
verification, CA overrides, SNI, and hostname checking.

The consumer currently places `send_timeout` and `send_timeout_close` in its
transport `socket_opts`. The ex_ssl adapter must translate the supported values
to ex_ssl's top-level connection options; it must reject remaining arbitrary TCP
options instead of dropping them. `send_timeout_close` must be `true`.

For custom profiles, apply the ALPN precedence rules in
[COMPATIBILITY.md](COMPATIBILITY.md). In particular, an explicit profile and
top-level HTTP ALPN list must match exactly, including order.

## Ownership, deadlines, and backpressure

Transfer ownership while still passive, before the connect worker exits. Do not
attempt to migrate active messages already delivered to the worker mailbox.
After `:ok`, worker exit is safe and new-owner death closes the connection.

One logical send is admitted at a time. A competing send returns `:busy`; the
adapter should treat that as a request failure, close, and never replay an
uncertain body. The logical send deadline is captured when admission begins.
Consumer request deadline/abort handling must still call `SSL.close/1`; this
interrupts blocked or infinite-timeout writes and cleans up the helper.

Application-passive mode does not disable internal TLS processing. Plaintext is
bounded to 1 MiB and raw reads pause near that boundary. Repeated active-once
delivery drains the buffer and resumes progress, permitting responses larger
than the bound without increasing it.

Internally, received TCP data and EOF/error events are held in arrival order in
a bounded FIFO whenever an output record is pending. After each bounded writer
completion, ex_ssl drains older input and safely rearms raw TCP before producing
the next application record. A several-MiB request therefore does not starve
response bytes or peer-requested KeyUpdate traffic, while a control response
still cannot overtake already-protected application ciphertext. Consumer calls
must not use repeated `setopts/2` as a polling mechanism for TLS progress.

All TLS output paths share the same connection-owned asynchronous writer.
Handshake deadlines include ClientHello/retry/client-Finished transport output;
logical send deadlines are not restarted by interleaved input or control
traffic. If an output is blocked and its result is uncertain, abort closes the
transport without replay rather than attempting to append close_notify behind
it.

An authenticated peer close that makes further application writes impossible
settles an unfinished admitted `SSL.send/2` promptly as `{:error, :closed}`.
This outbound settlement is independent of preserved inbound plaintext
drainage: a passive consumer may await the send result without calling `recv`,
then consume the response exactly once, followed by `{:error, :closed}`; an
active-once consumer receives buffered data before its terminal closure event.
The connection cancels the send timer, releases admission, demonitors the
sender, and discards the cursor and retained write state for that operation, so
an infinite or long send timeout does not delay the closure result and stale
completion messages cannot reply twice. A logical send already fully acknowledged
by the transport remains `:ok`; uncertain or partial bytes are not retried or
replayed. Abrupt transport failure keeps its existing error classification rather
than being converted to authenticated closure. Once authenticated closure is
accepted, failure of the reciprocal close-notify writer does not discard the
buffered response or reclassify the terminal state.

The existing Manifold passive direct-TLS and STARTTLS subset remains supported.
This work does not weaken its verification, plaintext-boundary, close, or
receive-timeout behavior.

## Consumer changes still required

1. Add explicit backend selection and a new transport module implementing the
   existing callbacks with `SSL`; keep OTP as the initial default.
2. Build TLS-1.3-specific ex_ssl options instead of copying the OTP adapter's
   mixed version defaults.
3. Dispatch negotiated-protocol lookup through the selected transport rather
   than pattern-matching specifically on `HTTP.Transport.SSL`.
4. Dispatch passive receive through the transport for the shared WebSocket HTTP
   Upgrade path; it currently calls `:ssl.recv` directly for SSL.
5. Broaden concrete socket types that currently assume OTP `:ssl.sslsocket()`.
6. Add adapter-level error mapping for `:busy`, ownership failures, ALPN absence,
   send timeout, graceful closure, and abrupt failure.

## Consumer acceptance checklist

Keep OTP as default while running both backends through the same scenarios.

HTTP/1.1:

- verified request with absent ALPN and with `http/1.1` selected;
- fixed-length, chunked, close-delimited, streaming, and several-MiB bodies;
- connect-worker transfer, task send, active-once response rearming;
- hostname/CA/depth failures, TLS 1.2-only peer, timeout, abort, and cleanup;
- WebSocket passive Upgrade receive followed by active-once frames.

HTTP/2:

- a real request/response with `h2` negotiated, not only an ALPN assertion;
- SETTINGS, flow-control, multiplexing, response streaming, and large-body
  behavior through the existing HTTP/2 implementation;
- cancellation and connection teardown with no replay or leaked task/socket.

Only those consumer tests can establish actual HTTP integration. The ex_ssl
fixture establishes that the underlying transport contract is available; this
library-only lifecycle behavior does not complete the separate http_fetch
adapter migration.
