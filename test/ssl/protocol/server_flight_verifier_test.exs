defmodule SSL.Protocol.ServerFlightVerifierTest do
  use ExUnit.Case, async: true
  use ExUnitProperties

  alias SSL.Crypto.{KeyExchange, KeySchedule}
  alias SSL.Crypto.KeyExchange.KeyPair
  alias SSL.Protocol.{HandshakeFramer, Record, ServerFlightVerifier, ServerHello, Transcript}
  alias SSL.Protocol.ServerFlightVerifier.{Input, Result}

  @fixture_dir Path.expand("../../fixtures/server_flight", __DIR__)
  @capture @fixture_dir
           |> Path.join("capture.txt")
           |> File.read!()
           |> String.split("\n", trim: true)
           |> Map.new(fn line ->
             [name, value] = String.split(line, "=", parts: 2)
             {String.to_atom(name), Base.decode16!(value)}
           end)
  @root_pem File.read!(Path.join(@fixture_dir, "root.pem"))
  @wrong_root_pem File.read!(Path.expand("../../fixtures/pkix/wrong_root.pem", __DIR__))

  test "verifies the captured fragmented and coalesced OpenSSL server flight" do
    assert {:ok,
            %Result{
              verified_peer: %{leaf_der: leaf_der},
              server_handshake_state: %{sequence: 3},
              client_handshake_state: %{sequence: 1},
              client_finished_record: client_finished_record,
              client_application_state: client_application,
              server_application_state: server_application,
              transcript: transcript
            } = result} = ServerFlightVerifier.verify(input())

    assert client_finished_record == @capture.client_finished_record
    assert Transcript.digest(transcript) == @capture.transcript_digest
    assert client_application.key == @capture.client_app_key
    assert client_application.iv == @capture.client_app_iv
    assert server_application.key == @capture.server_app_key
    assert server_application.iv == @capture.server_app_iv
    assert leaf_der == pem_der(Path.join(@fixture_dir, "leaf.pem"))

    inspected = inspect(result)
    refute inspected =~ Base.encode16(client_application.key)
    refute inspected =~ Base.encode16(server_application.key)
    refute inspected =~ Base.encode16(@capture.client_private)
  end

  test "maps tampered AEAD authentication to bad_record_mac" do
    [first | rest] = capture_records()

    assert {:error, {:fatal_alert, :bad_record_mac, :authentication_failed}} =
             ServerFlightVerifier.verify(input(records: [flip_last_bit(first) | rest]))
  end

  test "maps untrusted chains and wrong identities to certificate alerts" do
    assert {:error, {:fatal_alert, :unknown_ca, {:path_validation_failed, _reason}}} =
             ServerFlightVerifier.verify(input(trust_source: @wrong_root_pem))

    assert {:error, {:fatal_alert, :certificate_unknown, :hostname_mismatch}} =
             ServerFlightVerifier.verify(input(identity: {:dns_id, "wrong.example.test"}))
  end

  test "rejects invalid CertificateVerify and Finished with decrypt_error" do
    messages = captured_messages()
    invalid_signature = List.update_at(messages, 2, &flip_last_bit/1)
    invalid_finished = List.update_at(messages, 3, &flip_last_bit/1)

    assert {:error, {:fatal_alert, :decrypt_error, :invalid_certificate_verify}} =
             ServerFlightVerifier.verify(input(records: encrypt_messages(invalid_signature)))

    assert {:error, {:fatal_alert, :decrypt_error, :invalid_finished}} =
             ServerFlightVerifier.verify(input(records: encrypt_messages(invalid_finished)))
  end

  test "rejects empty, excessive, malformed, and incomplete record flights" do
    assert {:error, {:fatal_alert, :unexpected_message, :empty_server_flight}} =
             ServerFlightVerifier.verify(input(records: []))

    assert {:error, {:fatal_alert, :decode_error, {:record_count_limit_exceeded, 3, 2}}} =
             ServerFlightVerifier.verify(input(), max_records: 2)

    records_with_unchecked_tail = [<<>>, <<>>, <<>> | :not_a_list]

    assert {:error, {:fatal_alert, :decode_error, {:record_count_limit_exceeded, 3, 2}}} =
             ServerFlightVerifier.verify(input(records: records_with_unchecked_tail),
               max_records: 2
             )

    assert {:error, {:fatal_alert, :decode_error, {:record_length_mismatch, 124, 123}}} =
             ServerFlightVerifier.verify(
               input(records: [set_record_length(hd(capture_records()), 124)])
             )

    stream = IO.iodata_to_binary(captured_messages())
    incomplete = binary_part(stream, 0, byte_size(stream) - 1)

    assert {:error, {:fatal_alert, :decode_error, {:incomplete_handshake, _bytes}}} =
             ServerFlightVerifier.verify(input(records: encrypt_stream(incomplete)))
  end

  test "rejects out-of-order, duplicate, trailing, alert, and application data messages" do
    [encrypted_extensions, certificate, certificate_verify, finished] = captured_messages()

    out_of_order = [certificate, encrypted_extensions, certificate_verify, finished]
    duplicate = [encrypted_extensions, encrypted_extensions, certificate_verify, finished]
    trailing = [encrypted_extensions, certificate, certificate_verify, finished, finished]

    for messages <- [out_of_order, duplicate, trailing] do
      assert {:error, {:fatal_alert, :unexpected_message, _reason}} =
               ServerFlightVerifier.verify(input(records: encrypt_messages(messages)))
    end

    for type <- [:alert, :application_data] do
      assert {:error,
              {:fatal_alert, :unexpected_message, {:unexpected_inner_content_type, ^type}}} =
               ServerFlightVerifier.verify(
                 input(records: encrypt_stream(encrypted_extensions, type))
               )
    end
  end

  test "rejects HelloRetryRequest and key-share mismatches explicitly" do
    server_hello = server_hello()

    assert {:error, {:fatal_alert, :unexpected_message, {:unsupported, :hello_retry_request}}} =
             ServerFlightVerifier.verify(
               input(server_hello: %{server_hello | kind: :hello_retry_request})
             )

    wrong_pair = %{client_key_pair() | group: :secp256r1}

    assert {:error, {:fatal_alert, :illegal_parameter, {:key_share_group_mismatch, _, _}}} =
             ServerFlightVerifier.verify(input(client_key_pair: wrong_pair))
  end

  test "rejects malformed inputs and options with explicit fatal alerts" do
    assert {:error, {:fatal_alert, :decode_error, {:invalid_input, :verifier}}} =
             ServerFlightVerifier.verify(nil)

    assert {:error, {:fatal_alert, :decode_error, {:invalid_options, :verifier}}} =
             ServerFlightVerifier.verify(input(), nil)

    assert {:error, {:fatal_alert, :decode_error, {:invalid_options, :verifier}}} =
             ServerFlightVerifier.verify(input(), unknown: true)
  end

  test "rejects an improper ServerHello extension list without raising" do
    server_hello = %{server_hello() | extensions: [{:unknown, nil} | :not_a_list]}

    assert {:error, {:fatal_alert, :illegal_parameter, :malformed_server_hello_extensions}} =
             ServerFlightVerifier.verify(input(server_hello: server_hello))
  end

  test "rejects missing, duplicate, and PSK ServerHello key establishment" do
    server_hello = server_hello()
    key_share = Enum.find(server_hello.extensions, &match?({:key_share, _}, &1))

    assert {:error, {:fatal_alert, :illegal_parameter, :missing_key_share}} =
             ServerFlightVerifier.verify(
               input(
                 server_hello: %{
                   server_hello
                   | extensions: [{:supported_versions, 0x0304}]
                 }
               )
             )

    duplicate_key_share = %{server_hello | extensions: server_hello.extensions ++ [key_share]}

    assert {:error, {:fatal_alert, :illegal_parameter, :duplicate_key_share}} =
             ServerFlightVerifier.verify(input(server_hello: duplicate_key_share))

    psk = %{server_hello | extensions: server_hello.extensions ++ [{:pre_shared_key, 0}]}

    assert {:error, {:fatal_alert, :illegal_parameter, {:unsupported, :pre_shared_key}}} =
             ServerFlightVerifier.verify(input(server_hello: psk))
  end

  property "bounded malformed ServerHello extension entries return structured errors" do
    check all(
            extension <-
              member_of([nil, false, {:key_share}, {:key_share, nil}, {:unknown, nil}]),
            max_runs: 25
          ) do
      server_hello = %{server_hello() | extensions: [extension]}

      assert {:error, {:fatal_alert, :illegal_parameter, _reason}} =
               ServerFlightVerifier.verify(input(server_hello: server_hello))
    end
  end

  property "bounded malformed record flights return structured errors without raising" do
    check all(
            records <- list_of(binary(max_length: 64), max_length: 6),
            max_runs: 100
          ) do
      assert match?({:ok, %Result{}}, ServerFlightVerifier.verify(input(records: records))) or
               match?(
                 {:error, {:fatal_alert, _alert, _reason}},
                 ServerFlightVerifier.verify(input(records: records))
               )
    end
  end

  defp input(overrides \\ []) when is_list(overrides) do
    struct!(
      Input,
      Keyword.merge(
        [
          client_hello: @capture.client_hello,
          server_hello: server_hello(),
          client_key_pair: client_key_pair(),
          records: capture_records(),
          trust_source: @root_pem,
          identity: {:dns_id, "example.test"}
        ],
        overrides
      )
    )
  end

  defp server_hello do
    expectations = %{
      legacy_session_id: <<>>,
      offered_ciphers: [0x1301],
      offered_groups: [0x001D],
      offered_key_share_groups: [0x001D],
      offered_extension_ids: [10, 43, 51],
      offered_psk_key_exchange_modes: []
    }

    assert {:ok, server_hello, <<>>} = ServerHello.decode(@capture.server_hello, expectations)
    server_hello
  end

  # RFC 7748 section 6.1 deterministic scalar, used only as test-vector input.
  defp client_key_pair do
    %KeyPair{
      group: :x25519,
      public_key: @capture.client_public,
      private_key: @capture.client_private
    }
  end

  defp capture_records,
    do: [@capture.record_1, @capture.record_2, @capture.record_3]

  defp captured_messages do
    {messages, framer, _state} =
      Enum.reduce(capture_records(), {[], HandshakeFramer.new(), server_handshake_state()}, fn
        record, {messages, framer, state} ->
          assert {:ok, :handshake, plaintext, state} = Record.decrypt(state, record)
          assert {:ok, decoded, framer} = HandshakeFramer.feed(framer, plaintext)
          {messages ++ decoded, framer, state}
      end)

    assert HandshakeFramer.buffered_bytes(framer) == <<>>
    messages
  end

  defp encrypt_messages(messages), do: encrypt_stream(IO.iodata_to_binary(messages))

  defp encrypt_stream(stream, type \\ :handshake) do
    assert {:ok, record, _state} = Record.encrypt(server_handshake_state(), type, stream)
    [record]
  end

  defp server_handshake_state do
    server_hello = server_hello()

    {:key_share, %{key_exchange: peer_public}} =
      Enum.find(server_hello.extensions, &match?({:key_share, _}, &1))

    assert {:ok, shared_secret} = KeyExchange.shared_secret(client_key_pair(), peer_public)
    assert {:ok, early_secret} = KeySchedule.early_secret(:sha256, nil)

    assert {:ok, handshake_secret} =
             KeySchedule.handshake_secret(:sha256, early_secret, shared_secret)

    transcript =
      Transcript.new(:sha256)
      |> Transcript.append(@capture.client_hello)
      |> Transcript.append(server_hello.encoded)

    assert {:ok, traffic_secret} =
             KeySchedule.server_handshake_traffic_secret(
               :sha256,
               handshake_secret,
               Transcript.digest(transcript)
             )

    assert {:ok, state} =
             KeySchedule.traffic_state(:tls_aes_128_gcm_sha256, traffic_secret)

    state
  end

  defp pem_der(path) do
    [entry] = path |> File.read!() |> :public_key.pem_decode()
    elem(entry, 1)
  end

  defp set_record_length(<<type, version::16, _length::16, body::binary>>, length),
    do: <<type, version::16, length::16, body::binary>>

  defp flip_last_bit(binary) do
    prefix_size = byte_size(binary) - 1
    <<prefix::binary-size(^prefix_size), last>> = binary
    <<prefix::binary, Bitwise.bxor(last, 1)>>
  end
end
