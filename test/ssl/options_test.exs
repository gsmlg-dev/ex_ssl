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
          active: :once,
          packet: :line,
          mode: :list,
          verify: :verify_none,
          versions: [:"tlsv1.2"],
          depth: 5,
          customize_hostname_check: [fail_callback: fn _ -> true end]
        ] do
      assert {:error, {:options, _}} = SSL.Options.normalize(~c"mail.example", [option])
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
end
