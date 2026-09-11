defmodule ExSslE2E.Client do
  @moduledoc false

  alias SSL.ClientHello.{Materializer, Serializer, WireProfile}
  alias SSL.Protocol.{ClientOffer, HandshakeFramer, Record, ServerFlightVerifier, ServerHello}
  alias SSL.Protocol.ServerFlightVerifier.Input

  @capabilities %{
    versions: [:tlsv1_3],
    ciphers: [:tls_aes_128_gcm_sha256, :tls_aes_256_gcm_sha384],
    groups: [:x25519],
    signature_algorithms: [:ecdsa_secp256r1_sha256],
    key_share_sizes: %{x25519: 32}
  }

  @profile %WireProfile{
    name: :caddy_e2e,
    session_id: :random_32,
    cipher_suites: [:tls_aes_128_gcm_sha256, :tls_aes_256_gcm_sha384],
    extensions: [
      {:server_name, :from_connection},
      {:supported_groups, [:x25519]},
      {:ec_point_formats, [0]},
      {:signature_algorithms, [:ecdsa_secp256r1_sha256]},
      {:alpn, ["http/1.1"]},
      {:supported_versions, [:tlsv1_3]},
      {:key_share, [:x25519]}
    ]
  }

  @maximum_server_records 32

  def request(options) do
    host = Keyword.fetch!(options, :host)
    port = Keyword.fetch!(options, :port)
    timeout = Keyword.fetch!(options, :timeout)
    deadline = System.monotonic_time(:millisecond) + timeout

    with {:ok, materialized} <-
           Materializer.materialize(@profile, @capabilities, %{server_name: "localhost"}),
         {:ok, client_hello} <- Serializer.encode(materialized.client_hello),
         [client_key_pair] <- materialized.key_pairs,
         {:ok, offer} <- ClientOffer.from_client_hello(client_hello),
         {:ok, socket} <- connect(host, port, remaining(deadline)) do
      try do
        with :ok <- send_client_hello(socket, client_hello),
             {:ok, server_hello} <- receive_server_hello(socket, offer, deadline),
             {:ok, verified} <-
               receive_server_flight(
                 socket,
                 %Input{
                   client_hello: client_hello,
                   server_hello: server_hello,
                   client_key_pair: client_key_pair,
                   records: [],
                   trust_source: File.read!(Keyword.fetch!(options, :ca_file)),
                   identity: {:dns_id, "localhost"}
                 },
                 deadline
               ),
             :ok <- :gen_tcp.send(socket, verified.client_finished_record),
             {:ok, request_record, _client_state} <-
               Record.encrypt(
                 verified.client_application_state,
                 :application_data,
                 "GET /fingerprint HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
               ),
             :ok <- :gen_tcp.send(socket, request_record),
             {:ok, response} <-
               receive_http_response(socket, verified.server_application_state, deadline) do
          {:ok, response}
        end
      after
        :gen_tcp.close(socket)
      end
    else
      [] -> {:error, :missing_client_key_pair}
      {:error, reason} -> {:error, reason}
    end
  end

  defp connect(host, port, timeout) when timeout > 0 do
    case :gen_tcp.connect(
           String.to_charlist(host),
           port,
           [:binary, active: false, packet: :raw],
           timeout
         ) do
      {:ok, socket} -> {:ok, socket}
      {:error, reason} -> {:error, {:tcp_connect_failed, reason}}
    end
  end

  defp connect(_host, _port, _timeout), do: {:error, :tcp_connect_timeout}

  defp send_client_hello(socket, client_hello) do
    :gen_tcp.send(socket, <<22, 0x0301::16, byte_size(client_hello)::16, client_hello::binary>>)
  end

  defp receive_server_hello(socket, offer, deadline) do
    receive_server_hello(socket, offer, HandshakeFramer.new(), deadline)
  end

  defp receive_server_hello(socket, offer, framer, deadline) do
    with {:ok, record} <- receive_record(socket, deadline),
         {:ok, type, payload} <- plaintext_record(record) do
      case type do
        20 ->
          receive_server_hello(socket, offer, framer, deadline)

        22 ->
          with {:ok, messages, next_framer} <- HandshakeFramer.feed(framer, payload) do
            case messages do
              [] -> receive_server_hello(socket, offer, next_framer, deadline)
              [encoded] -> decode_server_hello(encoded, offer)
              _messages -> {:error, :unexpected_plaintext_server_handshake}
            end
          end

        unexpected ->
          {:error, {:unexpected_record_before_server_hello, unexpected}}
      end
    end
  end

  defp decode_server_hello(encoded, offer) do
    expectations = %{
      legacy_session_id: offer.legacy_session_id,
      offered_ciphers: offer.cipher_suites,
      offered_versions: offer.offered_versions,
      offered_groups: offer.supported_groups,
      offered_key_share_groups: Enum.map(offer.key_shares, & &1.group),
      offered_extension_ids: offer.extension_ids,
      offered_psk_key_exchange_modes: offer.psk_key_exchange_modes,
      offered_psk_count: offer.psk_count
    }

    case ServerHello.decode(encoded, expectations) do
      {:ok, server_hello, <<>>} ->
        {:ok, server_hello}

      {:ok, _server_hello, remainder} ->
        {:error, {:trailing_server_hello_bytes, byte_size(remainder)}}

      {:more, bytes} ->
        {:error, {:incomplete_server_hello, bytes}}

      {:error, reason} ->
        {:error, {:invalid_server_hello, reason}}
    end
  end

  defp receive_server_flight(socket, input, deadline) do
    receive_server_flight(socket, input, [], deadline)
  end

  defp receive_server_flight(_socket, _input, records, _deadline)
       when length(records) >= @maximum_server_records,
       do: {:error, {:server_flight_record_limit, @maximum_server_records}}

  defp receive_server_flight(socket, input, records, deadline) do
    with {:ok, record} <- receive_record(socket, deadline),
         {:ok, outer_type, _payload} <- plaintext_record(record) do
      case outer_type do
        20 ->
          receive_server_flight(socket, input, records, deadline)

        23 ->
          next_records = records ++ [record]

          case ServerFlightVerifier.verify(%{input | records: next_records}) do
            {:ok, result} ->
              {:ok, result}

            {:error, {:fatal_alert, :unexpected_message, {:invalid_server_flight_order, _}}} ->
              receive_server_flight(socket, input, next_records, deadline)

            {:error, {:fatal_alert, :decode_error, {:incomplete_handshake, _}}} ->
              receive_server_flight(socket, input, next_records, deadline)

            {:error, reason} ->
              {:error, {:server_flight_verification_failed, reason}}
          end

        unexpected ->
          {:error, {:unexpected_server_flight_record, unexpected}}
      end
    end
  end

  defp receive_http_response(socket, state, deadline) do
    receive_http_response(socket, state, <<>>, deadline)
  end

  defp receive_http_response(socket, state, response, deadline) do
    case complete_http_response(response) do
      {:ok, parsed} ->
        {:ok, parsed}

      {:error, _reason} = error ->
        error

      :more ->
        with {:ok, encrypted_record} <- receive_record(socket, deadline),
             {:ok, content_type, content, next_state} <- Record.decrypt(state, encrypted_record) do
          case content_type do
            :application_data ->
              receive_http_response(socket, next_state, response <> content, deadline)

            :handshake ->
              receive_http_response(socket, next_state, response, deadline)

            :alert ->
              {:error, {:tls_alert_before_complete_response, content}}
          end
        else
          {:error, reason} -> {:error, {:server_application_record_failed, reason}}
        end
    end
  end

  defp complete_http_response(response) do
    case :binary.match(response, "\r\n\r\n") do
      :nomatch ->
        :more

      {header_end, 4} ->
        headers = binary_part(response, 0, header_end)
        body_offset = header_end + 4
        body = binary_part(response, body_offset, byte_size(response) - body_offset)

        with [_, status] <- Regex.run(~r/^HTTP\/1\.1 (\d{3})/, headers),
             [_, length] <- Regex.run(~r/(?im)^content-length:\s*(\d+)\s*$/, headers),
             {content_length, ""} <- Integer.parse(length) do
          if byte_size(body) >= content_length do
            {:ok,
             %{
               status: String.to_integer(status),
               body: binary_part(body, 0, content_length)
             }}
          else
            :more
          end
        else
          _invalid -> {:error, {:invalid_http_response_headers, headers}}
        end
    end
  end

  defp receive_record(socket, deadline) do
    timeout = remaining(deadline)

    if timeout > 0 do
      with {:ok, <<type, version::16, length::16>>} <- :gen_tcp.recv(socket, 5, timeout),
           {:ok, payload} <- :gen_tcp.recv(socket, length, remaining(deadline)) do
        {:ok, <<type, version::16, length::16, payload::binary>>}
      else
        {:error, reason} -> {:error, {:tcp_receive_failed, reason}}
        other -> {:error, {:invalid_record_header, other}}
      end
    else
      {:error, :tcp_receive_timeout}
    end
  end

  defp plaintext_record(<<type, _version::16, length::16, payload::binary-size(length)>>),
    do: {:ok, type, payload}

  defp plaintext_record(_record), do: {:error, :malformed_tls_record}

  defp remaining(deadline), do: max(deadline - System.monotonic_time(:millisecond), 0)
end
