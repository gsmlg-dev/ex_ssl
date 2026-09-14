defmodule SSL.Options do
  @moduledoc false
  alias SSL.ClientHello.{Profile, WireProfile}

  @derive {Inspect, only: [:identity]}
  defstruct [:profile, :identity, :trust_source, context: %{}, hostname_check: []]
  @type t :: %__MODULE__{}

  @capabilities %{
    versions: [0x0304],
    ciphers: [0x1301, 0x1302, 0x1303],
    groups: [0x001D, 0x0017],
    signature_algorithms: [0x0403, 0x0804, 0x0805, 0x0806],
    psk_key_exchange_modes: [],
    raw_extensions: [],
    key_share_sizes: %{0x001D => 32, 0x0017 => 65}
  }
  @keys [
    :mode,
    :active,
    :packet,
    :verify,
    :cacerts,
    :cacertfile,
    :server_name_indication,
    :customize_hostname_check,
    :versions,
    :ex_ssl
  ]

  @spec capabilities() :: map()
  def capabilities do
    ciphers =
      available_identifiers(
        [
          {0x1301, :tls_aes_128_gcm_sha256, :aes_128_gcm},
          {0x1302, :tls_aes_256_gcm_sha384, :aes_256_gcm},
          {0x1303, :tls_chacha20_poly1305_sha256, :chacha20_poly1305}
        ],
        :ciphers
      )

    groups =
      available_identifiers(
        [{0x001D, :x25519, :x25519}, {0x0017, :secp256r1, :secp256r1}],
        :curves
      )

    signatures =
      available_identifiers(
        [
          {0x0403, :ecdsa_secp256r1_sha256, :ecdsa},
          {0x0804, :rsa_pss_rsae_sha256, :rsa},
          {0x0805, :rsa_pss_rsae_sha384, :rsa},
          {0x0806, :rsa_pss_rsae_sha512, :rsa}
        ],
        :public_keys
      )

    %{
      @capabilities
      | versions: [0x0304, :tlsv1_3],
        ciphers: ciphers,
        groups: groups,
        signature_algorithms: signatures
    }
  end

  defp available_identifiers(identifiers, capability) do
    available = :crypto.supports(capability)

    Enum.flat_map(identifiers, fn {id, name, primitive} ->
      if primitive in available, do: [id, name], else: []
    end)
  end

  @spec normalize(term(), term()) :: {:ok, t()} | {:error, term()}
  def normalize(host, options) do
    with {:ok, options} <- option_list(options),
         :ok <- validate_options(options),
         {:ok, identity, context} <-
           identity(host, Keyword.get(options, :server_name_indication)),
         {:ok, trust} <- trust_source(options),
         {:ok, profile} <- profile(options, context) do
      {:ok,
       %__MODULE__{
         profile: profile,
         identity: identity,
         context: context,
         trust_source: trust,
         hostname_check: Keyword.get(options, :customize_hostname_check, [])
       }}
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

  defp valid_option?(:mode, value), do: value == :binary
  defp valid_option?(:active, value), do: value == false
  defp valid_option?(:packet, value), do: value in [:raw, 0]
  defp valid_option?(:verify, value), do: value == :verify_peer
  defp valid_option?(:versions, value), do: value == [:"tlsv1.3"]
  defp valid_option?(:cacerts, value), do: is_list(value) and value != []

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
    profile = get_in(options, [:ex_ssl, :profile]) || :default
    profile = if profile == :default, do: default_profile(context), else: profile

    case Profile.validate(profile, capabilities()) do
      {:ok, profile} -> require_runtime_extensions(profile)
      {:error, _} -> option_error({:ex_ssl, :unsupported_profile})
    end
  end

  defp default_profile(context) do
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
          ]
    }
  end

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
