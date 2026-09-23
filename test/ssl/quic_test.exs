defmodule SSL.QUICTest do
  use ExUnit.Case, async: true
  use ExUnitProperties

  @fixtures Path.expand("../fixtures/server_flight", __DIR__)

  defp der(name) do
    [{:Certificate, der, :not_encrypted}] =
      File.read!(Path.join(@fixtures, name)) |> :public_key.pem_decode()

    der
  end

  defp server_options(extra \\ []) do
    [{type, key, :not_encrypted}] =
      File.read!(Path.join(@fixtures, "leaf-key.pem")) |> :public_key.pem_decode()

    Keyword.merge(
      [cert: [der("leaf.pem")], key: {type, key}, alpn: ["test"], transport_parameters: <<2, 0>>],
      extra
    )
  end

  defp client_options(extra \\ []) do
    Keyword.merge(
      [
        cacerts: [der("root.pem")],
        reference_identity: {:dns_id, "example.test"},
        alpn: ["test"],
        transport_parameters: <<1, 0>>
      ],
      extra
    )
  end

  test "real record-free certificate handshake exports paired directional secrets" do
    assert {:ok, client, client_actions} = SSL.QUIC.new(:client, client_options())
    assert [{:emit, :initial, <<1, _::binary>>}] = client_actions
    assert {:ok, server, []} = SSL.QUIC.new(:server, server_options())
    {client, server, ca, sa} = drive(client, server, client_actions, [], client_actions, [])
    assert %{handshake_complete: true, peer_authenticated: true} = SSL.QUIC.info(client)
    assert %{handshake_complete: true, peer_authenticated: false} = SSL.QUIC.info(server)

    for level <- [:handshake, :application], direction <- [:read, :write] do
      [left] = secrets(ca, level, direction)
      [right] = secrets(sa, level, if(direction == :read, do: :write, else: :read))
      assert left.secret == right.secret
      assert left.cipher_suite == right.cipher_suite
      refute inspect(left) =~ inspect(left.secret)
    end

    assert Enum.count(ca, &(&1 == :handshake_complete)) == 1
    assert Enum.count(sa, &(&1 == :handshake_complete)) == 1
    assert {:peer_transport_parameters, <<2, 0>>, :unverified} in ca
    assert {:peer_transport_parameters, <<2, 0>>, :authenticated} in ca
    assert {:ok, ^client, []} = SSL.QUIC.feed(client, :application, <<>>)
    assert {:ok, ^server, []} = SSL.QUIC.feed(server, :application, <<>>)
    assert_order(sa)
    assert_order(ca)
  end

  test "HRR uses the same client retry path and fresh requested share" do
    assert {:ok, client, out} = SSL.QUIC.new(:client, client_options(groups: [0x001D, 0x0017]))
    assert {:ok, server, []} = SSL.QUIC.new(:server, server_options(groups: [0x0017]))
    {client, server, ca, sa} = drive(client, server, out, [], out, [])
    assert %{handshake_complete: true} = SSL.QUIC.info(client)
    assert %{handshake_complete: true} = SSL.QUIC.info(server)
    assert [_, _] = Enum.filter(ca, &match?({:emit, :initial, _}, &1))
    assert [_, _] = Enum.filter(sa, &match?({:emit, :initial, _}, &1))
  end

  test "wrong level fails closed without exposing state and cannot restart" do
    assert {:ok, client, _} = SSL.QUIC.new(:client, client_options())
    assert {:error, error, failed, [_]} = SSL.QUIC.feed(client, :handshake, <<8, 0, 0, 2, 0, 0>>)
    assert error.kind == :quic
    assert %{phase: :failed, handshake_complete: false} = SSL.QUIC.info(failed)
    assert {:error, _, ^failed, []} = SSL.QUIC.feed(failed, :initial, <<>>)
  end

  test "all available cipher and group combinations derive matching keys" do
    caps = SSL.QUIC.capabilities()

    for suite <- Enum.filter(caps.cipher_suites, & &1.available),
        group <- Enum.filter(caps.groups, & &1.available) do
      opts = [ciphers: [suite.id], groups: [group.id]]
      {:ok, c, out} = SSL.QUIC.new(:client, client_options(opts))
      {:ok, s, []} = SSL.QUIC.new(:server, server_options(opts))
      {c, s, ca, sa} = drive(c, s, out, [], out, [])
      assert %{handshake_complete: true, cipher_suite: id} = SSL.QUIC.info(c)
      assert id == suite.id
      assert SSL.QUIC.info(s).handshake_complete

      for level <- [:handshake, :application] do
        [read] = secrets(ca, level, :read)
        [write] = secrets(sa, level, :write)
        assert read.secret == write.secret
        assert read.hkdf == suite.hash
        assert read.aead == suite.cipher
      end
    end
  end

  test "single-byte fragmentation and coalesced server flight preserve real handshake" do
    {:ok, c, [{:emit, :initial, ch}]} = SSL.QUIC.new(:client, client_options())
    {:ok, s, []} = SSL.QUIC.new(:server, server_options())
    {s, out} = feed_fragments(s, :initial, ch)
    [{:emit, :initial, sh}] = Enum.filter(out, &match?({:emit, :initial, _}, &1))
    {c, _} = feed_fragments(c, :initial, sh)
    handshake = for {:emit, :handshake, bytes} <- out, into: <<>>, do: bytes
    assert {:ok, c, co} = SSL.QUIC.feed(c, :handshake, handshake)
    client_flight = for {:emit, :handshake, bytes} <- co, into: <<>>, do: bytes
    {s, _} = feed_fragments(s, :handshake, client_flight)
    assert SSL.QUIC.info(c).handshake_complete
    assert SSL.QUIC.info(s).handshake_complete
  end

  test "no SNI does not disable reference-identity validation" do
    {:ok, c, co} =
      SSL.QUIC.new(:client, client_options(reference_identity: {:dns_id, "wrong.example.test"}))

    {:ok, s, []} = SSL.QUIC.new(:server, server_options())
    {_, so} = deliver(s, co)
    [{:emit, :initial, sh}] = Enum.filter(so, &match?({:emit, :initial, _}, &1))
    {:ok, c, _} = SSL.QUIC.feed(c, :initial, sh)
    bytes = for {:emit, :handshake, bytes} <- so, into: <<>>, do: bytes

    assert {:error, %{alert: :certificate_unknown, reason: :hostname_mismatch}, failed, [_]} =
             SSL.QUIC.feed(c, :handshake, bytes)

    refute SSL.QUIC.info(failed).handshake_complete
    refute SSL.QUIC.info(failed).peer_authenticated
    assert failed.core == nil
    assert failed.config == nil
  end

  test "missing transport parameters differ from an empty payload" do
    {:ok, c, co} = SSL.QUIC.new(:client, client_options(transport_parameters: <<>>))
    {:ok, s, []} = SSL.QUIC.new(:server, server_options(transport_parameters: <<>>))
    {_, _, ca, sa} = drive(c, s, co, [], co, [])
    assert {:peer_transport_parameters, <<>>, :authenticated} in ca
    assert {:peer_transport_parameters, <<>>, :authenticated} in sa
    [{:emit, :initial, ch}] = co
    missing = rewrite_extensions(ch, &Enum.reject(&1, fn {id, _} -> id == 57 end))
    assert {:error, %{alert: :missing_extension}, _, [_]} = SSL.QUIC.feed(s, :initial, missing)
    duplicate = rewrite_extensions(ch, &(&1 ++ [{57, <<>>}]))

    assert {:error, %{alert: :decode_error, reason: :duplicate_client_hello_extension}, _, [_]} =
             SSL.QUIC.feed(s, :initial, duplicate)
  end

  test "partial messages cannot cross encryption levels and declared lengths are bounded" do
    {:ok, c, _} = SSL.QUIC.new(:client, client_options())
    {:ok, c, []} = SSL.QUIC.feed(c, :initial, <<2, 0>>)
    assert {:error, %{kind: :quic}, _, [_]} = SSL.QUIC.feed(c, :handshake, <<0>>)
    {:ok, s, []} = SSL.QUIC.new(:server, server_options(limits: [max_handshake_length: 64]))

    assert {:error, %{alert: :decode_error, reason: :handshake_length_exceeded}, _, [_]} =
             SSL.QUIC.feed(s, :initial, <<1, 65::24>>)

    assert {:error, %{alert: :decode_error}, _, [_]} =
             SSL.QUIC.feed(s, :initial, <<22, 3, 3, 0, 1, 0>>)

    {:ok, s, []} = SSL.QUIC.new(:server, server_options(limits: [max_total_handshake_bytes: 10]))

    assert {:error, %{reason: :handshake_budget_exceeded}, _, [_]} =
             SSL.QUIC.feed(s, :initial, <<0::88>>)
  end

  test "unselected proposals and malformed key shares are handled distinctly" do
    {:ok, _, [{:emit, :initial, ch}]} = SSL.QUIC.new(:client, client_options())
    {:ok, s, []} = SSL.QUIC.new(:server, server_options())
    # A valid PSK offer can be declined in favor of certificate authentication.
    identity = <<1::16, "x", 0::32>>
    binder = <<32, 0::256>>
    psk = <<byte_size(identity)::16, identity::binary, byte_size(binder)::16, binder::binary>>
    offered = rewrite_extensions(ch, &(&1 ++ [{45, <<1, 1>>}, {41, psk}]))
    assert {:ok, _, actions} = SSL.QUIC.feed(s, :initial, offered)
    assert Enum.any?(actions, &match?({:emit, :handshake, <<11, _::binary>>}, &1))

    bad =
      rewrite_extensions(ch, fn extensions ->
        List.keyreplace(extensions, 51, 0, {51, <<5::16, 29::16, 1::16, 0>>})
      end)

    assert {:error, %{alert: :illegal_parameter}, _, [_]} = SSL.QUIC.feed(s, :initial, bad)
  end

  test "post-handshake tickets are bounded and ignored, KeyUpdate is rejected" do
    {:ok, c, co} = SSL.QUIC.new(:client, client_options())
    {:ok, s, []} = SSL.QUIC.new(:server, server_options())
    {c, _, _, _} = drive(c, s, co, [], co, [])
    ticket = <<3600::32, 0::32, 0, 1::16, "x", 0::16>>

    assert {:ok, next, []} =
             SSL.QUIC.feed(c, :application, <<4, byte_size(ticket)::24, ticket::binary>>)

    assert SSL.QUIC.info(next).handshake_complete

    assert {:error, %{alert: :unexpected_message}, _, [_]} =
             SSL.QUIC.feed(next, :application, <<24, 1::24, 0>>)

    assert %{phase: :aborted} = SSL.QUIC.info(SSL.QUIC.abort(c, :cancelled))
  end

  test "QUIC protocol errors differ from TLS alerts and optional PHA offers are ignored" do
    {:ok, c, co} = SSL.QUIC.new(:client, client_options())
    {:ok, s, []} = SSL.QUIC.new(:server, server_options())
    {c, _, _, _} = drive(c, s, co, [], co, [])

    assert {:error, %{kind: :quic, alert: nil, reason: :post_handshake_authentication}, _, [_]} =
             SSL.QUIC.feed(c, :application, <<13, 0::24>>)

    assert {:error, %{kind: :tls, alert: :unexpected_message}, _, [_]} =
             SSL.QUIC.feed(c, :application, <<5, 0::24>>)

    [{:emit, :initial, ch}] = co
    offered = rewrite_extensions(ch, &(&1 ++ [{49, <<>>}]))
    assert {:ok, _, _} = SSL.QUIC.feed(s, :initial, offered)
    <<1, size::24, version::16, random::binary-size(32), 0, rest::binary>> = ch
    session = <<1, size + 1::24, version::16, random::binary, 1, 0, rest::binary>>

    assert {:error, %{kind: :quic, reason: :quic_session_id}, _, [_]} =
             SSL.QUIC.feed(s, :initial, session)
  end

  test "unsupported or conflicting local configuration is rejected without output" do
    for opts <- [
          [resumption: true],
          [zero_rtt: true],
          [verify: :verify_none],
          [ciphers: [0x1304]],
          [record: :default],
          [alpn: []],
          [transport_parameters: nil],
          [limits: [unknown: 2]]
        ] do
      assert {:error, %{kind: :configuration}} = SSL.QUIC.new(:client, client_options(opts))
    end

    assert {:error, %{kind: :configuration}} =
             SSL.QUIC.new(:server, server_options(cacerts: [der("root.pem")]))
  end

  test "malformed profile extension containers return configuration errors" do
    for extensions <- [nil, 1, %{}, [1 | 2]] do
      profile = %SSL.ClientHello.WireProfile{
        session_id: :empty,
        record: %SSL.ClientHello.RecordPolicy{mode: :none},
        extensions: extensions
      }

      assert {:error, %{kind: :configuration}} =
               SSL.QUIC.new(:client, client_options(profile: profile))
    end
  end

  test "limits apply to emitted hellos, certificate configuration and peer extensions" do
    assert {:error, %{kind: :configuration}} =
             SSL.QUIC.new(:client, client_options(limits: [max_handshake_length: 64]))

    assert {:error, %{kind: :configuration}} =
             SSL.QUIC.new(
               :server,
               server_options(
                 cert: [der("leaf.pem"), der("root.pem")],
                 limits: [max_certificate_count: 1]
               )
             )

    {:ok, _, [{:emit, :initial, ch}]} = SSL.QUIC.new(:client, client_options())
    {:ok, s, []} = SSL.QUIC.new(:server, server_options(limits: [max_extension_bytes: 16]))

    assert {:error, %{alert: :decode_error, reason: :extension_length_exceeded}, _, [_]} =
             SSL.QUIC.feed(s, :initial, ch)
  end

  test "unknown PSK modes are unselected rather than malformed" do
    {:ok, _, [{:emit, :initial, ch}]} = SSL.QUIC.new(:client, client_options())
    {:ok, s, []} = SSL.QUIC.new(:server, server_options())
    ch = rewrite_extensions(ch, &(&1 ++ [{45, <<2, 1, 0xAB>>}]))
    assert {:ok, _, _} = SSL.QUIC.feed(s, :initial, ch)
  end

  test "both roles reject tampered CertificateVerify and Finished without completion" do
    for type <- [15, 20] do
      {:ok, c, co} = SSL.QUIC.new(:client, client_options())
      {:ok, s, []} = SSL.QUIC.new(:server, server_options())
      {_, so} = deliver(s, co)
      [{:emit, :initial, sh}] = Enum.filter(so, &match?({:emit, :initial, _}, &1))
      {:ok, c, _} = SSL.QUIC.feed(c, :initial, sh)

      flight =
        for {:emit, :handshake, bytes} <- so, into: <<>> do
          if :binary.first(bytes) == type, do: flip(bytes), else: bytes
        end

      assert {:error, %{alert: :decrypt_error}, failed, actions} =
               SSL.QUIC.feed(c, :handshake, flight)

      refute :handshake_complete in actions
      refute SSL.QUIC.info(failed).handshake_complete
    end

    {:ok, c, co} = SSL.QUIC.new(:client, client_options())
    {:ok, s, []} = SSL.QUIC.new(:server, server_options())
    {s, so} = deliver(s, co)
    {_, co} = deliver(c, so)
    [{:emit, :handshake, finished}] = Enum.filter(co, &match?({:emit, :handshake, _}, &1))

    assert {:error, %{alert: :decrypt_error}, failed, [_]} =
             SSL.QUIC.feed(s, :handshake, flip(finished))

    refute SSL.QUIC.info(failed).handshake_complete
    assert failed.core == nil
  end

  test "HRR cannot repeat or change the second ClientHello immutable fields" do
    {:ok, c, [{:emit, :initial, ch}]} = SSL.QUIC.new(:client, client_options(groups: [29, 23]))
    {:ok, s, []} = SSL.QUIC.new(:server, server_options(groups: [23]))
    {:ok, s, [{:emit, :initial, hrr}]} = SSL.QUIC.feed(s, :initial, ch)
    {:ok, c, [{:emit, :initial, ch2}]} = SSL.QUIC.feed(c, :initial, hrr)

    assert {:error, %{alert: :unexpected_message, reason: :second_hello_retry_request}, _, [_]} =
             SSL.QUIC.feed(c, :initial, hrr)

    <<prefix::binary-size(6), byte, rest::binary>> = ch2
    changed = <<prefix::binary, Bitwise.bxor(byte, 1), rest::binary>>

    assert {:error, %{alert: :illegal_parameter, reason: :retry_client_hello_changed}, _, [_]} =
             SSL.QUIC.feed(s, :initial, changed)
  end

  test "negotiation has no implicit algorithm or ALPN fallback" do
    {:ok, _, [{:emit, :initial, ch}]} =
      SSL.QUIC.new(:client, client_options(ciphers: [0x1301], groups: [29]))

    for {opts, alert, reason} <- [
          {[ciphers: [0x1302]], :handshake_failure, :no_shared_cipher},
          {[groups: [23]], :handshake_failure, :no_shared_group},
          {[alpn: ["other"]], :no_application_protocol, :no_application_protocol}
        ] do
      {:ok, s, []} = SSL.QUIC.new(:server, server_options(opts))
      assert {:error, %{alert: ^alert, reason: ^reason}, _, [_]} = SSL.QUIC.feed(s, :initial, ch)
    end
  end

  test "peer certificate, signature and aggregate budgets fail before completion" do
    for limits <- [
          [max_certificate_count: 1],
          [max_certificate_bytes: 32],
          [max_total_certificate_bytes: 32],
          [max_signature_bytes: 1]
        ] do
      {:ok, c, co} = SSL.QUIC.new(:client, client_options(limits: limits))

      {:ok, s, []} =
        SSL.QUIC.new(:server, server_options(cert: [der("leaf.pem"), der("root.pem")]))

      {_, out} = deliver(s, co)
      [{:emit, :initial, sh}] = Enum.filter(out, &match?({:emit, :initial, _}, &1))
      {:ok, c, _} = SSL.QUIC.feed(c, :initial, sh)
      bytes = for {:emit, :handshake, bytes} <- out, into: <<>>, do: bytes
      assert {:error, _, failed, actions} = SSL.QUIC.feed(c, :handshake, bytes)
      refute :handshake_complete in actions
      assert failed.core == nil
    end

    assert {:error, %{kind: :configuration}} =
             SSL.QUIC.new(:server, server_options(limits: [max_certificate_bytes: 32]))

    assert {:error, %{kind: :configuration}} =
             SSL.QUIC.new(:server, server_options(limits: [max_total_certificate_bytes: 32]))

    {:ok, _, [{:emit, :initial, ch}]} = SSL.QUIC.new(:client, client_options())

    {:ok, s, []} =
      SSL.QUIC.new(:server, server_options(limits: [max_total_handshake_bytes: byte_size(ch)]))

    assert {:error, %{reason: :handshake_budget_exceeded}, _, [_]} =
             SSL.QUIC.feed(s, :initial, ch)
  end

  test "unoffered suite and unknown handshake types never negotiate" do
    {:ok, c, co} = SSL.QUIC.new(:client, client_options(ciphers: [0x1301]))
    {:ok, s, []} = SSL.QUIC.new(:server, server_options())
    {_, out} = deliver(s, co)
    [{:emit, :initial, sh}] = Enum.filter(out, &match?({:emit, :initial, _}, &1))
    <<prefix::binary-size(39), _suite::16, rest::binary>> = sh

    assert {:error, %{alert: :illegal_parameter}, _, [_]} =
             SSL.QUIC.feed(c, :initial, <<prefix::binary, 0x1302::16, rest::binary>>)

    for type <- [5, 24, 255] do
      assert {:error, %{alert: :unexpected_message}, _, [_]} =
               SSL.QUIC.feed(s, :initial, <<type, 0::24>>)
    end
  end

  test "malformed known client extension payloads and configuration are structured errors" do
    {:ok, _, [{:emit, :initial, ch}]} = SSL.QUIC.new(:client, client_options())
    {:ok, s, []} = SSL.QUIC.new(:server, server_options())

    for {id, payload} <- [{0, <<>>}, {0, <<0, 1, 0>>}, {49, <<1>>}, {21, <<1>>}] do
      changed = rewrite_extensions(ch, &(&1 ++ [{id, payload}]))
      assert {:error, %{alert: :decode_error}, _, [_]} = SSL.QUIC.feed(s, :initial, changed)
    end

    for extra <- [
          [customize_hostname_check: [123]],
          [limits: [123]],
          [ciphers: [nil]],
          [alpn: [nil]]
        ] do
      assert {:error, %{kind: :configuration}} = SSL.QUIC.new(:client, client_options(extra))
    end
  end

  property "arbitrary bounded Initial bytes never escape structured framing results" do
    {:ok, server, []} = SSL.QUIC.new(:server, server_options())

    check all(bytes <- binary(max_length: 512), max_runs: 80) do
      case SSL.QUIC.feed(server, :initial, bytes) do
        {:ok, _, _} -> :ok
        {:error, %SSL.QUIC.Error{}, state, _} -> assert SSL.QUIC.info(state).phase == :failed
      end
    end
  end

  test "transport parameters are required once in EE and forbidden in other server messages" do
    {:ok, client, co} = SSL.QUIC.new(:client, client_options())
    {:ok, server, []} = SSL.QUIC.new(:server, server_options())
    {_, out} = deliver(server, co)
    [{:emit, :initial, sh}] = Enum.filter(out, &match?({:emit, :initial, _}, &1))
    <<2, length::24, prefix::binary-size(38), ext_size::16, extensions::binary>> = sh

    bad_sh =
      <<2, length + 4::24, prefix::binary, ext_size + 4::16, extensions::binary, 57::16, 0::16>>

    assert {:error, _, _, [_]} = SSL.QUIC.feed(client, :initial, bad_sh)
    {:ok, client, _} = SSL.QUIC.feed(client, :initial, sh)
    alpn = <<16::16, 7::16, 5::16, 4, "test">>

    for {tp, reason} <- [
          {<<>>, :missing_extension},
          {<<57::16, 0::16, 57::16, 0::16>>, :decode_error}
        ] do
      ee =
        <<8, byte_size(alpn) + byte_size(tp) + 2::24, byte_size(alpn) + byte_size(tp)::16,
          alpn::binary, tp::binary>>

      assert {:error, %{alert: ^reason}, _, [_]} = SSL.QUIC.feed(client, :handshake, ee)
    end

    [{:emit, :handshake, ee} | _] = Enum.filter(out, &match?({:emit, :handshake, _}, &1))
    {:ok, client, _} = SSL.QUIC.feed(client, :handshake, ee)
    # CertificateRequest has a valid signature list, but extension 57 is illegal here.
    request = <<0, 12::16, 13::16, 4::16, 2::16, 0x0403::16, 57::16, 0::16>>
    leaf = der("leaf.pem")
    entry = <<byte_size(leaf)::24, leaf::binary, 4::16, 57::16, 0::16>>
    certificate = <<0, byte_size(entry)::24, entry::binary>>

    for {type, body} <- [{13, request}, {11, certificate}] do
      assert {:error, _, failed, [_]} =
               SSL.QUIC.feed(client, :handshake, <<type, byte_size(body)::24, body::binary>>)

      refute SSL.QUIC.info(failed).handshake_complete
    end

    {:ok, client, co} = SSL.QUIC.new(:client, client_options())
    {:ok, server, []} = SSL.QUIC.new(:server, server_options())
    {client, _, _, _} = drive(client, server, co, [], co, [])
    ticket = <<3600::32, 0::32, 0, 1::16, "x", 4::16, 57::16, 0::16>>

    assert {:error, %{alert: :decode_error}, _, [_]} =
             SSL.QUIC.feed(client, :application, <<4, byte_size(ticket)::24, ticket::binary>>)
  end

  defp flip(bytes) do
    size = byte_size(bytes) - 1
    <<prefix::binary-size(^size), byte>> = bytes
    <<prefix::binary, Bitwise.bxor(byte, 1)>>
  end

  defp feed_fragments(state, level, bytes) do
    Enum.reduce(:binary.bin_to_list(bytes), {state, []}, fn byte, {state, out} ->
      assert {:ok, state, actions} = SSL.QUIC.feed(state, level, <<byte>>)
      {state, out ++ actions}
    end)
  end

  defp rewrite_extensions(<<1, _::24, body::binary>>, fun) do
    <<_version::16, _random::binary-size(32), sid_length, rest::binary>> = body
    <<_sid::binary-size(^sid_length), suites_length::16, rest::binary>> = rest
    <<_suites::binary-size(^suites_length), compression_length, rest::binary>> = rest

    <<_compression::binary-size(^compression_length), extensions_length::16,
      raw::binary-size(extensions_length)>> = rest

    prefix_size = byte_size(body) - extensions_length - 2
    prefix = binary_part(body, 0, prefix_size)
    extensions = parse_extensions(raw)

    raw =
      fun.(extensions)
      |> Enum.map(fn {id, payload} -> <<id::16, byte_size(payload)::16, payload::binary>> end)
      |> IO.iodata_to_binary()

    body = <<prefix::binary, byte_size(raw)::16, raw::binary>>
    <<1, byte_size(body)::24, body::binary>>
  end

  defp parse_extensions(<<>>), do: []

  defp parse_extensions(<<id::16, size::16, payload::binary-size(size), rest::binary>>),
    do: [{id, payload} | parse_extensions(rest)]

  defp drive(client, server, [], [], ca, sa), do: {client, server, ca, sa}

  defp drive(client, server, co, so, ca, sa) do
    {server, next_so} = deliver(server, co)
    {client, next_co} = deliver(client, so)
    drive(client, server, next_co, next_so, ca ++ next_co, sa ++ next_so)
  end

  defp deliver(state, actions) do
    Enum.reduce(actions, {state, []}, fn
      {:emit, level, bytes}, {state, out} ->
        assert {:ok, next, actions} = SSL.QUIC.feed(state, level, bytes)
        {next, out ++ actions}

      _, acc ->
        acc
    end)
  end

  defp secrets(actions, level, direction),
    do:
      Enum.filter(actions, fn
        %{level: ^level, direction: ^direction, secret: _} -> true
        _ -> false
      end)

  defp assert_order(actions) do
    Enum.reduce(actions, MapSet.new([:initial]), fn
      %{direction: :write, level: level, secret: _}, installed ->
        MapSet.put(installed, level)

      {:emit, level, _}, installed ->
        assert MapSet.member?(installed, level)
        installed

      _, installed ->
        installed
    end)
  end
end
