defmodule SSL.Options do
  @moduledoc false
  alias SSL.ClientHello.{Profile, WireProfile}
  alias SSL.Capabilities

  @derive {Inspect, only: [:identity]}
  defstruct [
    :profile,
    :identity,
    :trust_source,
    :client_identity,
    :alpn_advertised_protocols,
    active: false,
    depth: 10,
    send_timeout: 5_000,
    send_timeout_close: true,
    context: %{},
    hostname_check: []
  ]

  @type t :: %__MODULE__{}

  @keys [
    :mode,
    :active,
    :packet,
    :depth,
    :send_timeout,
    :send_timeout_close,
    :verify,
    :cacerts,
    :cacertfile,
    :cert,
    :certfile,
    :key,
    :keyfile,
    :server_name_indication,
    :customize_hostname_check,
    :versions,
    :alpn_advertised_protocols,
    :ex_ssl
  ]

  @spec capabilities() :: map()
  def capabilities do
    %{
      versions: [0x0304, :tlsv1_3],
      ciphers: Capabilities.identifiers(:cipher_suite),
      groups: Capabilities.identifiers(:group),
      signature_algorithms: Capabilities.identifiers(:signature_algorithm),
      certificate_signature_algorithms:
        Capabilities.identifiers(:certificate_signature_algorithm),
      psk_key_exchange_modes: [],
      raw_extensions: [],
      key_share_sizes: Capabilities.key_share_sizes()
    }
  end

  @spec normalize(term(), term()) :: {:ok, t()} | {:error, term()}
  def normalize(host, options) do
    with {:ok, options} <- option_list(options),
         :ok <- validate_options(options),
         {:ok, identity, context} <-
           identity(host, Keyword.get(options, :server_name_indication)),
         {:ok, trust} <- trust_source(options),
         {:ok, profile} <- profile(options, context),
         {:ok, client_identity} <-
           SSL.ClientIdentity.load(Keyword.take(options, [:cert, :certfile, :key, :keyfile])) do
      {:ok,
       %__MODULE__{
         profile: profile,
         identity: identity,
         context: context,
         trust_source: trust,
         client_identity: client_identity,
         alpn_advertised_protocols: profile_alpn(profile),
         active: Keyword.get(options, :active, false),
         depth: Keyword.get(options, :depth, 10),
         send_timeout: Keyword.get(options, :send_timeout, 5_000),
         send_timeout_close: Keyword.get(options, :send_timeout_close, true),
         hostname_check: Keyword.get(options, :customize_hostname_check, [])
       }}
    end
  end

  @spec normalize_setopts(term()) :: {:ok, keyword()} | {:error, term()}
  def normalize_setopts(options) do
    with {:ok, options} <- option_list(options),
         :ok <- validate_setopts(options) do
      {:ok, options}
    end
  end

  @spec deadline(timeout()) :: {:ok, integer() | :infinity} | {:error, :badarg}
  def deadline(:infinity), do: {:ok, :infinity}

  def deadline(timeout) when is_integer(timeout) and timeout >= 0 do
    now = System.monotonic_time(:millisecond)
    deadline = now + timeout

    if deadline <= timer_end_time(), do: {:ok, deadline}, else: {:error, :badarg}
  end

  def deadline(_), do: {:error, :badarg}

  @spec remaining(integer() | :infinity) :: timeout()
  def remaining(:infinity), do: :infinity
  def remaining(deadline), do: max(0, deadline - System.monotonic_time(:millisecond))

  defp timer_end_time do
    :erlang.system_info(:end_time)
    |> :erlang.convert_time_unit(:native, :millisecond)
  end

  defp option_list(options) when is_list(options) do
    normalized =
      Enum.map(options, fn
        :binary -> {:mode, :binary}
        other -> other
      end)

    if Keyword.keyword?(normalized) and
         length(Keyword.keys(normalized)) == length(Enum.uniq(Keyword.keys(normalized))),
       do: {:ok, normalized},
       else: option_error(:invalid_options)
  end

  defp option_list(_), do: option_error(:invalid_options)

  defp validate_options(options) do
    Enum.reduce_while(options, :ok, fn {key, value}, :ok ->
      if key in @keys and valid_option?(key, value),
        do: {:cont, :ok},
        else: {:halt, option_error({key, :unsupported_or_invalid})}
    end)
  end

  defp validate_setopts(options) do
    Enum.reduce_while(options, :ok, fn {key, value}, :ok ->
      if key in [:active, :send_timeout, :send_timeout_close] and valid_option?(key, value),
        do: {:cont, :ok},
        else: {:halt, option_error({key, :unsupported_or_invalid})}
    end)
  end

  defp valid_option?(:mode, value), do: value == :binary
  defp valid_option?(:active, value), do: value in [false, :once]
  defp valid_option?(:packet, value), do: value in [:raw, 0]
  defp valid_option?(:depth, value), do: is_integer(value) and value >= 0

  defp valid_option?(:send_timeout, :infinity), do: true

  defp valid_option?(:send_timeout, value) when is_integer(value) and value >= 0,
    do: match?({:ok, _deadline}, deadline(value))

  defp valid_option?(:send_timeout, _value), do: false

  defp valid_option?(:send_timeout_close, value), do: value == true
  defp valid_option?(:verify, value), do: value == :verify_peer
  defp valid_option?(:versions, value), do: value == [:"tlsv1.3"]
  defp valid_option?(:alpn_advertised_protocols, value), do: valid_alpn_protocols?(value)
  defp valid_option?(:cacerts, value), do: is_list(value) and value != []

  # The identity loader owns shape, size, source-conflict and key matching checks.
  defp valid_option?(key, _value) when key in [:cert, :certfile, :key, :keyfile], do: true

  defp valid_option?(:cacertfile, value),
    do: (is_binary(value) or is_list(value)) and value not in ["", []]

  defp valid_option?(:server_name_indication, value),
    do: value == :disable or match?({:ok, _}, dns_name(value))

  defp valid_option?(:customize_hostname_check, value) do
    value == [] or
      (Keyword.keyword?(value) and length(value) == 1 and is_function(value[:match_fun], 2))
  end

  defp valid_option?(:ex_ssl, value) do
    Keyword.keyword?(value) and Keyword.keys(value) == [:profile] and
      (value[:profile] == :default or match?(%WireProfile{}, value[:profile]))
  end

  defp identity(_host, sni) when sni not in [nil, :disable] do
    with {:ok, name} <- dns_name(sni), do: {:ok, {:dns_id, name}, %{server_name: name}}
  end

  defp identity(:upgrade, _), do: option_error({:server_name_indication, :required_for_upgrade})

  defp identity(host, sni) do
    case host_identity(host) do
      {:ok, {:dns_id, name} = identity} ->
        {:ok, identity, if(sni == :disable, do: %{}, else: %{server_name: name})}

      {:ok, {:ip, _} = identity} ->
        {:ok, identity, %{}}

      :error ->
        option_error({:host, :invalid})
    end
  end

  defp host_identity(host) when is_tuple(host) do
    case :inet.ntoa(host) do
      {:error, _} -> :error
      _ -> {:ok, {:ip, host}}
    end
  catch
    _, _ -> :error
  end

  defp host_identity(host) do
    with {:ok, name} <- dns_name(host) do
      case :inet.parse_address(String.to_charlist(name)) do
        {:ok, ip} -> {:ok, {:ip, ip}}
        {:error, _} -> {:ok, {:dns_id, name}}
      end
    else
      _ -> :error
    end
  end

  defp dns_name(name) when is_list(name) do
    dns_name(List.to_string(name))
  rescue
    _ -> option_error({:server_name_indication, :invalid})
  end

  defp dns_name(name) when is_binary(name) and byte_size(name) in 1..253 do
    if String.valid?(name) and
         Regex.match?(~r/\A[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9.])?\z/, name),
       do: {:ok, name},
       else: option_error({:server_name_indication, :invalid})
  end

  defp dns_name(_), do: option_error({:server_name_indication, :invalid})

  defp trust_source(options) do
    case {Keyword.fetch(options, :cacerts), Keyword.fetch(options, :cacertfile)} do
      {{:ok, certificates}, _} ->
        validate_trust(certificates)

      {:error, {:ok, path}} ->
        case File.read(path) do
          {:ok, pem} -> validate_trust(pem)
          {:error, _} -> option_error({:cacertfile, :unreadable})
        end

      {:error, :error} ->
        validate_trust(:public_key.cacerts_get())
    end
  rescue
    _ -> option_error({:cacerts, :invalid})
  end

  defp validate_trust(source) do
    case SSL.PKIX.normalize_trust(source) do
      {:ok, _} -> {:ok, source}
      {:error, _} -> option_error({:cacerts, :invalid})
    end
  end

  defp profile(options, context) do
    advertised_protocols = Keyword.get(options, :alpn_advertised_protocols)
    explicit_profile? = Keyword.has_key?(options, :ex_ssl)
    profile = get_in(options, [:ex_ssl, :profile]) || :default

    with {:ok, profile} <-
           if(profile == :default,
             do: {:ok, default_profile(context, advertised_protocols)},
             else: resolve_explicit_profile(profile, advertised_protocols, explicit_profile?)
           ) do
      validate_profile(profile)
    end
  end

  defp validate_profile(profile) do
    case Profile.validate(profile, capabilities()) do
      {:ok, profile} -> require_runtime_extensions(profile)
      {:error, _} -> option_error({:ex_ssl, :unsupported_profile})
    end
  end

  defp resolve_explicit_profile(profile, nil, _explicit_profile?), do: {:ok, profile}

  defp resolve_explicit_profile(profile, protocols, true) do
    if profile_alpn(profile) == protocols do
      {:ok, profile}
    else
      option_error({:alpn_advertised_protocols, :profile_conflict})
    end
  end

  defp default_profile(context, alpn_protocols) do
    capabilities = capabilities()
    groups = Enum.filter(capabilities.groups, &is_integer/1)

    %WireProfile{
      name: :default,
      cipher_suites: Enum.filter(capabilities.ciphers, &is_integer/1),
      extensions:
        if(Map.has_key?(context, :server_name), do: [{:server_name, :from_connection}], else: []) ++
          [
            {:supported_versions, [0x0304]},
            {:supported_groups, groups},
            {:signature_algorithms,
             Enum.filter(capabilities.signature_algorithms, &is_integer/1)},
            {:key_share, Enum.take(groups, 1)}
          ] ++ alpn_extension(alpn_protocols)
    }
  end

  defp alpn_extension(nil), do: []
  defp alpn_extension(protocols), do: [{:alpn, protocols}]

  defp profile_alpn(%WireProfile{extensions: extensions}) do
    Enum.find_value(extensions, fn
      {:alpn, protocols} -> protocols
      _extension -> nil
    end)
  end

  defp profile_alpn(_profile), do: nil

  defp valid_alpn_protocols?(protocols) when is_list(protocols) and protocols != [] do
    Enum.all?(protocols, &(is_binary(&1) and byte_size(&1) in 1..255)) and
      Enum.reduce(protocols, 2, fn protocol, size -> size + 1 + byte_size(protocol) end) <= 0xFFFF
  end

  defp valid_alpn_protocols?(_protocols), do: false

  defp require_runtime_extensions(profile) do
    required = [:supported_versions, :supported_groups, :signature_algorithms, :key_share]

    if Enum.all?(required, fn name ->
         Enum.any?(profile.extensions, fn
           {^name, [_ | _]} -> true
           _ -> false
         end)
       end),
       do: {:ok, profile},
       else: option_error({:ex_ssl, :incomplete_profile})
  end

  defp option_error(reason), do: {:error, {:options, reason}}
end
