defmodule SSL.OptionsTest do
  use ExUnit.Case, async: true

  test "consumer binary/passive/raw options retain DNS identity independently of IP routing" do
    opts = [
      :binary,
      active: false,
      packet: :raw,
      verify: :verify_peer,
      cacerts: :public_key.cacerts_get(),
      server_name_indication: ~c"mail.example",
      customize_hostname_check: [match_fun: :public_key.pkix_verify_hostname_match_fun(:https)]
    ]

    assert {:ok, options} = SSL.Options.normalize({127, 0, 0, 1}, opts)
    assert options.identity == {:dns_id, "mail.example"}
    assert options.context == %{server_name: "mail.example"}
    assert options.hostname_check[:match_fun]
  end

  test "rejects unsupported security and socket options" do
    for option <- [
          active: true,
          packet: :line,
          mode: :list,
          verify: :verify_none,
          versions: [:"tlsv1.2"],
          customize_hostname_check: [fail_callback: fn _ -> true end]
        ] do
      assert {:error, {:options, _}} = SSL.Options.normalize(~c"mail.example", [option])
    end
  end

  test "normalizes active-once, depth, and send policy without accepting weaker variants" do
    assert {:ok, %{active: :once, depth: 2, send_timeout: :infinity, send_timeout_close: true}} =
             SSL.Options.normalize("mail.example",
               active: :once,
               depth: 2,
               send_timeout: :infinity,
               send_timeout_close: true
             )

    for option <- [
          active: true,
          depth: -1,
          depth: 1.5,
          send_timeout: -1,
          send_timeout: 1.5,
          send_timeout_close: false
        ] do
      assert {:error, {:options, _}} = SSL.Options.normalize("mail.example", [option])
    end

    end_time =
      :erlang.system_info(:end_time)
      |> :erlang.convert_time_unit(:native, :millisecond)

    unrepresentable_timeout = end_time - System.monotonic_time(:millisecond) + 1_000

    assert {:error, {:options, _}} =
             SSL.Options.normalize("mail.example", send_timeout: unrepresentable_timeout)
  end

  test "normalizes a complete setopts request atomically" do
    assert {:ok, [active: :once, send_timeout: :infinity, send_timeout_close: true]} =
             SSL.Options.normalize_setopts(
               active: :once,
               send_timeout: :infinity,
               send_timeout_close: true
             )

    for options <- [
          [active: :once, active: false],
          [packet: :raw],
          [depth: 1],
          [send_timeout_close: false],
          [unknown: :value]
        ] do
      assert {:error, {:options, _}} = SSL.Options.normalize_setopts(options)
    end
  end

  test "adds ordered ALPN to the default profile" do
    assert {:ok, %{profile: profile, alpn_advertised_protocols: ["h2", "http/1.1"]}} =
             SSL.Options.normalize("mail.example", alpn_advertised_protocols: ["h2", "http/1.1"])

    assert {:alpn, ["h2", "http/1.1"]} = Enum.find(profile.extensions, &match?({:alpn, _}, &1))
  end

  test "requires an exact ALPN match for an explicit profile" do
    profile = default_profile_with_alpn(["h2", "http/1.1"])

    assert {:ok, %{profile: ^profile}} =
             SSL.Options.normalize("mail.example",
               ex_ssl: [profile: profile],
               alpn_advertised_protocols: ["h2", "http/1.1"]
             )

    assert {:error, {:options, {:alpn_advertised_protocols, :profile_conflict}}} =
             SSL.Options.normalize("mail.example",
               ex_ssl: [profile: profile],
               alpn_advertised_protocols: ["http/1.1", "h2"]
             )
  end

  test "does not inject top-level ALPN into an explicit profile without ALPN" do
    profile = default_profile_with_alpn(nil)

    assert {:error, {:options, {:alpn_advertised_protocols, :profile_conflict}}} =
             SSL.Options.normalize("mail.example",
               ex_ssl: [profile: profile],
               alpn_advertised_protocols: ["h2"]
             )
  end

  test "rejects malformed or oversized ALPN lists before connecting" do
    for protocols <- [
          [],
          [""],
          [:h2],
          [String.duplicate("a", 256)],
          List.duplicate("a", 32_768)
        ] do
      assert {:error, {:options, {:alpn_advertised_protocols, :unsupported_or_invalid}}} =
               SSL.Options.normalize("mail.example", alpn_advertised_protocols: protocols)
    end
  end

  test "validates malformed options and timeouts without making a connection" do
    for options <- [
          nil,
          %{},
          [:invalid],
          [{:active, false, :extra}],
          [active: false, active: false]
        ] do
      assert {:error, {:options, _}} = SSL.Options.normalize(~c"mail.example", options)
    end

    for timeout <- [-1, 1.0, nil, :invalid] do
      assert {:error, :badarg} = SSL.Options.deadline(timeout)
    end

    end_time =
      :erlang.system_info(:end_time)
      |> :erlang.convert_time_unit(:native, :millisecond)

    unrepresentable_timeout = end_time - System.monotonic_time(:millisecond) + 1_000
    assert {:error, :badarg} = SSL.Options.deadline(unrepresentable_timeout)
    assert {:ok, _deadline} = SSL.Options.deadline(4_294_967_296)

    assert {:ok, :infinity} = SSL.Options.deadline(:infinity)
    assert {:ok, deadline} = SSL.Options.deadline(0)
    assert SSL.Options.remaining(deadline) == 0
  end

  test "upgrade requires an explicit reference identity" do
    assert {:error, {:options, _}} = SSL.Options.normalize(:upgrade, [])

    assert {:ok, %{identity: {:dns_id, "mail.example"}}} =
             SSL.Options.normalize(:upgrade, server_name_indication: ~c"mail.example")
  end

  test "IP connection never fabricates SNI" do
    assert {:ok, options} = SSL.Options.normalize({127, 0, 0, 1}, [])
    assert options.identity == {:ip, {127, 0, 0, 1}}
    assert options.context == %{}
    refute Enum.any?(options.profile.extensions, &match?({:server_name, _}, &1))
  end

  test "incomplete profiles are rejected before a TCP connection is attempted" do
    assert {:error, {:options, _}} =
             SSL.Options.normalize("mail.example",
               ex_ssl: [profile: %SSL.ClientHello.WireProfile{}]
             )
  end

  test "rejects explicit certificate signature policy until chain enforcement exists" do
    assert {:ok, %{profile: profile}} = SSL.Options.normalize("mail.example", [])

    profile = %{
      profile
      | extensions: profile.extensions ++ [{:signature_algorithms_cert, [0x0403]}]
    }

    assert {:error, {:options, {:ex_ssl, :unsupported_profile}}} =
             SSL.Options.normalize("mail.example", ex_ssl: [profile: profile])
  end

  defp default_profile_with_alpn(protocols) do
    assert {:ok, %{profile: profile}} = SSL.Options.normalize("mail.example", [])

    extensions =
      case protocols do
        nil -> profile.extensions
        protocols -> profile.extensions ++ [{:alpn, protocols}]
      end

    %{profile | extensions: extensions}
  end
end
