defmodule SSL.Protocol.HandshakeMachineTest do
  use ExUnit.Case, async: true

  alias SSL.ClientHello.{AST, Extension, Serializer}
  alias SSL.ClientHello.Materializer.Materialized
  alias SSL.Crypto.{KeyExchange, KeySchedule}
  alias SSL.Crypto.KeyExchange.KeyPair
  alias SSL.Protocol.{ClientOffer, HandshakeMachine, Record, ServerFlight}

  @fixture_dir Path.expand("../../fixtures/server_flight", __DIR__)
  @capture Path.join(@fixture_dir, "capture.txt")
           |> File.read!()
           |> String.split("\n", trim: true)
           |> Map.new(fn line ->
             [name, value] = String.split(line, "=", parts: 2)
             {String.to_atom(name), Base.decode16!(value)}
           end)

  test "incrementally authenticates a fragmented encrypted flight and emits client Finished" do
    materialized = fixture_materialized()

    assert {:ok, machine, [client_hello_record]} = fixture_machine(materialized)

    assert client_hello_record == plaintext_record(@capture.client_hello)

    assert {:ok, machine, [], []} =
             HandshakeMachine.feed(machine, plaintext_record(@capture.server_hello))

    assert {:ok, machine, [], []} = HandshakeMachine.feed(machine, @capture.record_1)
    assert {:ok, machine, [], []} = HandshakeMachine.feed(machine, @capture.record_2)

    assert {:ok, _machine, [client_finished], [:connected]} =
             HandshakeMachine.feed(machine, @capture.record_3)

    assert client_finished == @capture.client_finished_record
  end

  test "continues application traffic through a requested peer KeyUpdate" do
    {:ok, machine, _outbound} = fixture_machine(fixture_materialized())

    {:ok, machine, [], []} =
      HandshakeMachine.feed(machine, plaintext_record(@capture.server_hello))

    {:ok, machine, [], []} = HandshakeMachine.feed(machine, @capture.record_1)
    {:ok, machine, [], []} = HandshakeMachine.feed(machine, @capture.record_2)
    {:ok, machine, [_finished], [:connected]} = HandshakeMachine.feed(machine, @capture.record_3)

    server_write = machine.read_state
    client_read = machine.write_state
    {:ok, record, _server_write} = Record.encrypt(server_write, :application_data, "one")

    assert {:ok, machine, [], [{:application_data, "one"}]} =
             HandshakeMachine.feed(machine, record)

    {:ok, update, _server_old} =
      Record.encrypt(
        machine.read_state,
        :handshake,
        elem(ServerFlight.encode_key_update(true), 1)
      )

    assert {:ok, machine, [response], []} = HandshakeMachine.feed(machine, update)
    assert machine.read_state.generation == 1
    assert machine.read_state.sequence == 0
    assert machine.write_state.generation == 1
    assert machine.write_state.sequence == 0

    assert {:ok, :handshake, <<24, 1::24, 0>>, _old_client_read} =
             Record.decrypt(client_read, response)

    {:ok, next_server_secret} = KeySchedule.traffic_update(:sha384, server_write.secret)

    {:ok, next_server_write} =
      KeySchedule.traffic_state(server_write.cipher_suite, next_server_secret)

    {:ok, record, _} = Record.encrypt(next_server_write, :application_data, "two")

    assert {:ok, _machine, [], [{:application_data, "two"}]} =
             HandshakeMachine.feed(machine, record)
  end

  test "validates and discards NewSessionTicket and rejects other post-handshake messages" do
    machine = connected_fixture_machine()
    ticket = <<4, 15::24, 60::32, 7::32, 1, 9, 1::16, 1, 0::16>>
    {:ok, record, _} = Record.encrypt(machine.read_state, :handshake, ticket)
    assert {:ok, machine, [], []} = HandshakeMachine.feed(machine, record)

    {:ok, record, _} = Record.encrypt(machine.read_state, :handshake, <<8, 2::24, 0::16>>)

    assert {:error, {:fatal_alert, :unexpected_message, _}} =
             HandshakeMachine.feed(machine, record)
  end

  test "HelloRetryRequest preserves ClientHello fields and generates a fresh selected share" do
    {:ok, first_pair} = KeyExchange.generate(:x25519)
    {:ok, groups} = Extension.encode({:supported_groups, [0x001D, 0x0017]})
    {:ok, versions} = Extension.encode({:supported_versions, [0x0304]})
    {:ok, shares} = Extension.encode({:key_share, [{0x001D, first_pair.public_key}]})

    ast = %AST{
      legacy_version: 0x0303,
      random: <<7::256>>,
      session_id: <<8, 9>>,
      cipher_suites: [0x1301],
      compression_methods: [0],
      extensions: [groups, versions, shares]
    }

    materialized = %Materialized{client_hello: ast, key_pairs: [first_pair]}

    assert {:ok, machine, [_]} =
             HandshakeMachine.init(
               materialized,
               [@capture.client_public],
               {:dns_id, "example.test"}
             )

    hrr_random =
      Base.decode16!("CF21AD74E59A6111BE1D8C021E65B891C2A211167ABB8C5E079E09E2C8A8339C")

    hrr =
      hello(hrr_random, ast.session_id, 0x1301, [
        extension(43, <<0x0304::16>>),
        extension(51, <<0x0017::16>>)
      ])

    assert {:ok, retried, [record], []} = HandshakeMachine.feed(machine, plaintext_record(hrr))
    <<22, 3, 3, _::16, client_hello2::binary>> = record
    assert {:ok, offer} = ClientOffer.from_client_hello(client_hello2)
    assert [%{group: 0x0017, key_exchange: second_public}] = offer.key_shares
    refute second_public == first_pair.public_key
    assert retried.client_ast.random == ast.random
    assert retried.client_ast.session_id == ast.session_id
    assert retried.client_ast.cipher_suites == ast.cipher_suites
    assert Enum.at(retried.client_ast.extensions, 0) == groups
  end

  test "fragments a large ClientHello and incrementally frames ServerHello" do
    {:ok, pair} = KeyExchange.generate(:x25519)
    {:ok, versions} = Extension.encode({:supported_versions, [0x0304]})
    {:ok, groups} = Extension.encode({:supported_groups, [0x001D]})
    {:ok, shares} = Extension.encode({:key_share, [{0x001D, pair.public_key}]})

    ast = %AST{
      legacy_version: 0x0303,
      random: <<3::256>>,
      session_id: <<>>,
      cipher_suites: [0x1301],
      compression_methods: [0],
      extensions: [versions, groups, shares, {21, :binary.copy(<<0>>, 20_000)}]
    }

    assert {:ok, encoded} = Serializer.encode(ast)

    assert {:ok, machine, [first, second]} =
             HandshakeMachine.init(
               %Materialized{client_hello: ast, key_pairs: [pair]},
               [@capture.client_public],
               {:dns_id, "example.test"}
             )

    assert <<22, 3, 3, 16_384::16, first_bytes::binary>> = first
    assert byte_size(first_bytes) == 16_384
    assert <<22, 3, 3, second_size::16, second_bytes::binary>> = second
    assert second_size == byte_size(second_bytes)
    assert first_bytes <> second_bytes == encoded

    {:ok, peer} = KeyExchange.generate(:x25519)

    hello =
      hello(<<4::256>>, <<>>, 0x1301, [
        extension(43, <<0x0304::16>>),
        extension(51, <<0x001D::16, 32::16, peer.public_key::binary>>)
      ])

    split = div(byte_size(hello), 2)
    <<left::binary-size(^split), right::binary>> = hello
    assert {:ok, machine, [], []} = HandshakeMachine.feed(machine, plaintext_record(left))

    assert {:ok, %{phase: :await_server_flight}, [], []} =
             HandshakeMachine.feed(machine, plaintext_record(right))
  end

  test "selects the ephemeral key pair matching the server-selected offered share" do
    {:ok, x} = KeyExchange.generate(:x25519)
    {:ok, p256} = KeyExchange.generate(:secp256r1)
    {:ok, versions} = Extension.encode({:supported_versions, [0x0304]})
    {:ok, groups} = Extension.encode({:supported_groups, [0x001D, 0x0017]})

    {:ok, shares} =
      Extension.encode({:key_share, [{0x001D, x.public_key}, {0x0017, p256.public_key}]})

    ast = %AST{
      legacy_version: 0x0303,
      random: <<5::256>>,
      session_id: <<>>,
      cipher_suites: [0x1301],
      compression_methods: [0],
      extensions: [versions, groups, shares]
    }

    {:ok, machine, _} =
      HandshakeMachine.init(
        %Materialized{client_hello: ast, key_pairs: [x, p256]},
        [@capture.client_public],
        {:dns_id, "example.test"}
      )

    {:ok, peer} = KeyExchange.generate(:secp256r1)

    hello =
      hello(<<6::256>>, <<>>, 0x1301, [
        extension(43, <<0x0304::16>>),
        extension(51, <<0x0017::16, 65::16, peer.public_key::binary>>)
      ])

    assert {:ok, selected, [], []} = HandshakeMachine.feed(machine, plaintext_record(hello))
    assert selected.key_pair.group == :secp256r1
  end

  test "rejects complete and partial handshake bytes after server Finished" do
    machine = fixture_before_finished()

    {:ok, :handshake, finished_fragment, _} =
      Record.decrypt(machine.read_state, @capture.record_3)

    for suffix <- [<<8, 2::24, 0::16>>, <<8>>] do
      {:ok, record, _} =
        Record.encrypt(machine.read_state, :handshake, finished_fragment <> suffix)

      assert {:error, {:fatal_alert, _, _}} = HandshakeMachine.feed(machine, record)
    end
  end

  test "rejects bytes after KeyUpdate before changing epochs and classifies peer alerts" do
    machine = connected_fixture_machine()
    update_and_ticket = <<24, 1::24, 0, 4, 15::24, 60::32, 7::32, 1, 9, 1::16, 1, 0::16>>
    {:ok, record, _} = Record.encrypt(machine.read_state, :handshake, update_and_ticket)

    assert {:error, {:fatal_alert, :decode_error, :trailing_message_after_key_update}} =
             HandshakeMachine.feed(machine, record)

    {:ok, alert, _} = Record.encrypt(machine.read_state, :alert, <<2, 40>>)
    assert {:error, {:peer_alert, 2, 40}} = HandshakeMachine.feed(machine, alert)
  end

  test "accepts plaintext peer alerts only before ServerHello and preserves encrypted handshake alerts" do
    {:ok, initial, _} = fixture_machine(fixture_materialized())
    plaintext_alert = <<21, 3, 3, 2::16, 2, 40>>
    assert {:error, {:peer_alert, 2, 40}} = HandshakeMachine.feed(initial, plaintext_alert)

    {:ok, handshaking, [], []} =
      HandshakeMachine.feed(initial, plaintext_record(@capture.server_hello))

    assert {:error, {:fatal_alert, :unexpected_message, :unprotected_alert_after_server_hello}} =
             HandshakeMachine.feed(handshaking, plaintext_alert)

    {:ok, encrypted_alert, _} = Record.encrypt(handshaking.read_state, :alert, <<2, 40>>)
    assert {:error, {:peer_alert, 2, 40}} = HandshakeMachine.feed(handshaking, encrypted_alert)

    {:ok, application, _} =
      Record.encrypt(handshaking.read_state, :application_data, "premature")

    assert {:error,
            {:fatal_alert, :unexpected_message,
             {:unexpected_inner_content_type, :application_data}}} =
             HandshakeMachine.feed(handshaking, application)
  end

  test "rejects application data interleaved with a fragmented post-handshake message" do
    machine = connected_fixture_machine()
    {:ok, partial, server_write} = Record.encrypt(machine.read_state, :handshake, <<4, 0>>)
    assert {:ok, machine, [], []} = HandshakeMachine.feed(machine, partial)

    {:ok, application, _server_write} =
      Record.encrypt(server_write, :application_data, "interleaved")

    assert {:error, {:fatal_alert, :unexpected_message, :interleaved_post_handshake_record}} =
             HandshakeMachine.feed(machine, application)
  end

  defp fixture_materialized do
    %Materialized{
      client_hello: %AST{
        legacy_version: 0x0303,
        random: <<0::256>>,
        session_id: <<>>,
        cipher_suites: [0x1302],
        compression_methods: [0],
        extensions: []
      },
      key_pairs: [
        %KeyPair{
          group: :x25519,
          public_key: @capture.client_public,
          private_key: @capture.client_private
        }
      ]
    }
  end

  defp fixture_machine(materialized),
    do:
      HandshakeMachine.init(
        materialized,
        File.read!(Path.join(@fixture_dir, "root.pem")),
        {:dns_id, "example.test"},
        encoded_client_hello: @capture.client_hello
      )

  defp connected_fixture_machine do
    {:ok, machine, _} = fixture_machine(fixture_materialized())

    {:ok, machine, [], []} =
      HandshakeMachine.feed(machine, plaintext_record(@capture.server_hello))

    {:ok, machine, [], []} = HandshakeMachine.feed(machine, @capture.record_1)
    {:ok, machine, [], []} = HandshakeMachine.feed(machine, @capture.record_2)
    {:ok, machine, [_], [:connected]} = HandshakeMachine.feed(machine, @capture.record_3)
    machine
  end

  defp fixture_before_finished do
    {:ok, machine, _} = fixture_machine(fixture_materialized())

    {:ok, machine, [], []} =
      HandshakeMachine.feed(machine, plaintext_record(@capture.server_hello))

    {:ok, machine, [], []} = HandshakeMachine.feed(machine, @capture.record_1)
    {:ok, machine, [], []} = HandshakeMachine.feed(machine, @capture.record_2)
    machine
  end

  defp hello(random, session_id, cipher, extensions) do
    extension_bytes = IO.iodata_to_binary(extensions)

    body =
      <<0x0303::16, random::binary, byte_size(session_id), session_id::binary, cipher::16, 0,
        byte_size(extension_bytes)::16, extension_bytes::binary>>

    <<2, byte_size(body)::24, body::binary>>
  end

  defp extension(id, payload), do: <<id::16, byte_size(payload)::16, payload::binary>>

  defp plaintext_record(handshake), do: <<22, 3, 3, byte_size(handshake)::16, handshake::binary>>
end
