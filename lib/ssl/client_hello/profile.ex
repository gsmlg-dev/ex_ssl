defmodule SSL.ClientHello.Profile do
  @moduledoc """
  Validates wire profiles against explicit engine/runtime capabilities.

  Validation is intentionally fail-closed. Raw extensions require a specific
  extension ID in the optional `:raw_extensions` capability allowlist.
  """

  alias SSL.ClientHello.{GreasePolicy, RecordPolicy, WireProfile}

  @extension_ids %{
    server_name: 0,
    supported_groups: 10,
    ec_point_formats: 11,
    signature_algorithms: 13,
    alpn: 16,
    padding: 21,
    pre_shared_key: 41,
    supported_versions: 43,
    psk_key_exchange_modes: 45,
    signature_algorithms_cert: 50,
    key_share: 51
  }

  @typed_extension_ids Map.values(@extension_ids)
  @known_key_share_sizes %{x25519: 32, secp256r1: 65}

  @typedoc "Capabilities the current TLS engine can safely advertise."
  @type capabilities :: %{
          required(:versions) => [WireProfile.version()],
          required(:ciphers) => [WireProfile.cipher_suite()],
          required(:groups) => [WireProfile.group()],
          optional(:raw_extensions) => [0..0xFFFF],
          optional(:signature_algorithms) => [atom() | 0..0xFFFF],
          optional(:psk_key_exchange_modes) => [atom() | 0..0xFF],
          optional(:key_share_sizes) => %{optional(WireProfile.group()) => pos_integer()}
        }

  @spec validate(WireProfile.t(), capabilities()) :: {:ok, WireProfile.t()} | {:error, term()}
  def validate(%WireProfile{} = profile, capabilities) do
    with :ok <- validate_capabilities(capabilities),
         :ok <- validate_profile_shape(profile),
         :ok <- validate_extension_shapes(profile.extensions),
         :ok <- validate_duplicate_extensions(profile.extensions),
         :ok <- validate_pre_shared_key_position(profile.extensions),
         :ok <- validate_alpn(profile.extensions),
         :ok <- validate_grease(profile.extensions),
         :ok <- validate_raw_extensions(profile.extensions, capabilities),
         :ok <- validate_versions(profile.extensions, capabilities.versions),
         :ok <- validate_ciphers(profile.cipher_suites, capabilities.ciphers),
         :ok <- validate_groups(profile.extensions, capabilities.groups),
         :ok <- validate_signature_algorithms(profile.extensions, capabilities),
         :ok <- validate_psk_modes(profile.extensions, capabilities),
         :ok <- validate_key_shares(profile.extensions, capabilities),
         :ok <- validate_group_relationships(profile.extensions),
         :ok <- validate_extensions_length(profile.extensions, capabilities) do
      {:ok, profile}
    end
  end

  def validate(_profile, _capabilities), do: {:error, {:invalid_profile, :structure}}

  defp validate_capabilities(capabilities) when is_map(capabilities) do
    with :ok <- require_capability_list(capabilities, :versions),
         :ok <- require_capability_list(capabilities, :ciphers),
         :ok <- require_capability_list(capabilities, :groups),
         :ok <- validate_optional_capability_list(capabilities, :signature_algorithms),
         :ok <- validate_optional_capability_list(capabilities, :psk_key_exchange_modes),
         :ok <- validate_raw_extension_capability(capabilities),
         :ok <- validate_key_share_size_capability(capabilities) do
      :ok
    end
  end

  defp validate_capabilities(_capabilities), do: {:error, {:invalid_capabilities, :structure}}

  defp require_capability_list(capabilities, key) do
    case Map.fetch(capabilities, key) do
      {:ok, value} when is_list(value) -> :ok
      _other -> {:error, {:invalid_capabilities, key}}
    end
  end

  defp validate_optional_capability_list(capabilities, key) do
    case Map.fetch(capabilities, key) do
      :error -> :ok
      {:ok, value} when is_list(value) -> :ok
      {:ok, _value} -> {:error, {:invalid_capabilities, key}}
    end
  end

  defp validate_raw_extension_capability(capabilities) do
    case Map.fetch(capabilities, :raw_extensions) do
      :error ->
        :ok

      {:ok, extension_ids} when is_list(extension_ids) ->
        if Enum.all?(extension_ids, &valid_uint16?/1) do
          :ok
        else
          {:error, {:invalid_capabilities, :raw_extensions}}
        end

      {:ok, _other} ->
        {:error, {:invalid_capabilities, :raw_extensions}}
    end
  end

  defp validate_key_share_size_capability(capabilities) do
    case Map.fetch(capabilities, :key_share_sizes) do
      :error ->
        :ok

      {:ok, sizes} when is_map(sizes) ->
        if Enum.all?(sizes, fn {group, size} ->
             valid_protocol_identifier?(group) and is_integer(size) and size > 0 and
               size <= 0xFFFF
           end) do
          :ok
        else
          {:error, {:invalid_capabilities, :key_share_sizes}}
        end

      {:ok, _sizes} ->
        {:error, {:invalid_capabilities, :key_share_sizes}}
    end
  end

  defp validate_profile_shape(%WireProfile{} = profile) do
    with :ok <- require_profile(profile.legacy_version == 0x0303, :legacy_version),
         :ok <- require_profile(valid_session_id?(profile.session_id), :session_id),
         :ok <- require_profile(valid_cipher_suites?(profile.cipher_suites), :cipher_suites),
         :ok <- require_profile(profile.compression_methods == [0], :compression_methods),
         :ok <- require_profile(is_list(profile.extensions), :extensions),
         :ok <- require_profile(profile.grease == %GreasePolicy{mode: :disabled}, :grease),
         :ok <- require_profile(profile.record == %RecordPolicy{mode: :default}, :record) do
      :ok
    end
  end

  defp require_profile(true, _field), do: :ok
  defp require_profile(false, field), do: {:error, {:invalid_profile, field}}

  defp valid_session_id?(:random_32), do: true
  defp valid_session_id?(:empty), do: true

  defp valid_session_id?({:fixed, session_id}) when is_binary(session_id),
    do: byte_size(session_id) <= 32

  defp valid_session_id?(_policy), do: false

  defp valid_cipher_suites?(cipher_suites) when is_list(cipher_suites) do
    length(cipher_suites) in 1..32_767 and
      Enum.all?(cipher_suites, &valid_protocol_identifier?/1) and
      Enum.uniq(cipher_suites) == cipher_suites
  end

  defp valid_cipher_suites?(_cipher_suites), do: false

  defp validate_extension_shapes(extensions) do
    case Enum.find(extensions, &(not valid_extension?(&1))) do
      nil -> :ok
      extension -> {:error, {:invalid_extension, extension}}
    end
  end

  defp valid_extension?({:server_name, :from_connection}), do: true
  defp valid_extension?({:supported_groups, groups}), do: uint16_vector?(groups)
  defp valid_extension?({:ec_point_formats, formats}), do: uint8_integer_vector?(formats)
  defp valid_extension?({:signature_algorithms, algorithms}), do: uint16_vector?(algorithms)
  defp valid_extension?({:signature_algorithms_cert, algorithms}), do: uint16_vector?(algorithms)
  defp valid_extension?({:alpn, protocols}), do: is_list(protocols)
  defp valid_extension?({:supported_versions, versions}), do: version_vector?(versions)
  defp valid_extension?({:psk_key_exchange_modes, modes}), do: uint8_vector?(modes)
  defp valid_extension?({:key_share, groups}), do: protocol_identifier_list?(groups)
  defp valid_extension?({:pre_shared_key, :deferred}), do: true
  defp valid_extension?({:padding, :none}), do: true

  defp valid_extension?({:padding, size}) when is_integer(size) and size in 0..0xFFFF,
    do: true

  defp valid_extension?({:padding, {:fixed, size}})
       when is_integer(size) and size in 0..0xFFFF,
       do: true

  defp valid_extension?({:grease, slot}) when is_atom(slot), do: true

  defp valid_extension?({:raw, extension_id, payload}) do
    valid_uint16?(extension_id) and is_binary(payload) and byte_size(payload) <= 0xFFFF
  end

  defp valid_extension?(_extension), do: false

  defp protocol_identifier_list?(values) when is_list(values) do
    Enum.all?(values, &valid_protocol_identifier?/1)
  end

  defp protocol_identifier_list?(_values), do: false

  defp valid_protocol_identifier?(value) when is_atom(value), do: true
  defp valid_protocol_identifier?(value), do: valid_uint16?(value)

  defp uint16_vector?(values) when is_list(values) do
    length(values) in 1..32_766 and Enum.all?(values, &valid_protocol_identifier?/1)
  end

  defp uint16_vector?(_values), do: false

  defp version_vector?(values) when is_list(values) do
    length(values) in 1..127 and Enum.all?(values, &valid_protocol_identifier?/1)
  end

  defp version_vector?(_values), do: false

  defp uint8_vector?(values) when is_list(values) do
    length(values) in 1..255 and
      Enum.all?(values, &(is_atom(&1) or (is_integer(&1) and &1 in 0..0xFF)))
  end

  defp uint8_vector?(_values), do: false

  defp uint8_integer_vector?(values) when is_list(values) do
    length(values) in 1..255 and Enum.all?(values, &(is_integer(&1) and &1 in 0..0xFF))
  end

  defp uint8_integer_vector?(_values), do: false

  defp valid_uint16?(value), do: is_integer(value) and value in 0..0xFFFF

  defp validate_duplicate_extensions(extensions) do
    extensions
    |> Enum.reduce_while(MapSet.new(), fn extension, seen ->
      identity = extension_identity(extension)

      if MapSet.member?(seen, identity) do
        {:halt, {:error, {:duplicate_extension, identity}}}
      else
        {:cont, MapSet.put(seen, identity)}
      end
    end)
    |> case do
      %MapSet{} -> :ok
      error -> error
    end
  end

  defp extension_identity({:raw, extension_id, _payload}), do: extension_id
  defp extension_identity({:grease, slot}), do: {:grease, slot}
  defp extension_identity(extension), do: Map.fetch!(@extension_ids, elem(extension, 0))

  defp validate_pre_shared_key_position(extensions) do
    extensions
    |> Enum.with_index()
    |> Enum.find(fn {extension, index} ->
      extension_identity(extension) == @extension_ids.pre_shared_key and
        index != length(extensions) - 1
    end)
    |> case do
      nil -> :ok
      _extension -> {:error, :pre_shared_key_must_be_last}
    end
  end

  defp validate_alpn(extensions) do
    case Enum.find_value(extensions, &alpn_protocols/1) do
      nil -> :ok
      protocols -> if valid_alpn?(protocols), do: :ok, else: {:error, :invalid_alpn}
    end
  end

  defp alpn_protocols({:alpn, protocols}), do: protocols
  defp alpn_protocols(_extension), do: nil

  defp valid_alpn?([]), do: false

  defp valid_alpn?(protocols) do
    Enum.all?(protocols, &(is_binary(&1) and byte_size(&1) in 1..255)) and
      Enum.reduce(protocols, 0, fn protocol, size -> size + 1 + byte_size(protocol) end) <=
        0xFFFF - 2
  end

  defp validate_grease(extensions) do
    if Enum.any?(extensions, &match?({:grease, _slot}, &1)) do
      {:error, :grease_not_supported}
    else
      :ok
    end
  end

  defp validate_raw_extensions(extensions, capabilities) do
    allowed = Map.get(capabilities, :raw_extensions, [])

    case Enum.find(extensions, fn
           {:raw, extension_id, _payload} when extension_id in @typed_extension_ids -> true
           {:raw, extension_id, _payload} -> extension_id not in allowed
           _extension -> false
         end) do
      {:raw, extension_id, _payload} when extension_id in @typed_extension_ids ->
        {:error, {:raw_extension_requires_typed_form, extension_id}}

      {:raw, extension_id, _payload} ->
        {:error, {:raw_extension_not_allowed, extension_id}}

      nil ->
        :ok
    end
  end

  defp validate_versions(extensions, supported_versions) do
    versions =
      Enum.flat_map(extensions, fn
        {:supported_versions, versions} -> versions
        _extension -> []
      end)

    reject_unsupported(versions, supported_versions, :unsupported_versions)
  end

  defp validate_ciphers(cipher_suites, supported_ciphers) do
    reject_unsupported(cipher_suites, supported_ciphers, :unsupported_ciphers)
  end

  defp validate_groups(extensions, supported_groups) do
    groups =
      Enum.flat_map(extensions, fn
        {:supported_groups, groups} -> groups
        {:key_share, groups} -> groups
        _extension -> []
      end)

    reject_unsupported(groups, supported_groups, :unsupported_groups)
  end

  defp validate_signature_algorithms(extensions, capabilities) do
    algorithms =
      Enum.flat_map(extensions, fn
        {:signature_algorithms, algorithms} -> algorithms
        {:signature_algorithms_cert, algorithms} -> algorithms
        _extension -> []
      end)

    reject_unsupported(
      algorithms,
      Map.get(capabilities, :signature_algorithms, []),
      :unsupported_signature_algorithms
    )
  end

  defp validate_psk_modes(extensions, capabilities) do
    modes =
      Enum.flat_map(extensions, fn
        {:psk_key_exchange_modes, modes} -> modes
        _extension -> []
      end)

    reject_unsupported(
      modes,
      Map.get(capabilities, :psk_key_exchange_modes, []),
      :unsupported_psk_key_exchange_modes
    )
  end

  defp validate_key_shares(extensions, capabilities) do
    groups =
      Enum.flat_map(extensions, fn
        {:key_share, groups} -> groups
        _extension -> []
      end)

    with :ok <- reject_duplicates(groups, :duplicate_key_share),
         :ok <- require_key_share_sizes(groups, capabilities) do
      :ok
    end
  end

  defp validate_group_relationships(extensions) do
    supported_groups = Enum.find(extensions, &match?({:supported_groups, _groups}, &1))
    key_shares = Enum.find(extensions, &match?({:key_share, _groups}, &1))

    with :ok <- reject_supported_group_duplicates(supported_groups) do
      case {supported_groups, key_shares} do
        {nil, nil} ->
          :ok

        {nil, {:key_share, _groups}} ->
          {:error, :key_share_requires_supported_groups}

        {{:supported_groups, _groups}, nil} ->
          {:error, :supported_groups_requires_key_share}

        {{:supported_groups, supported_groups}, {:key_share, key_shares}} ->
          require_ordered_subset(key_shares, supported_groups)
      end
    end
  end

  defp reject_supported_group_duplicates(nil), do: :ok

  defp reject_supported_group_duplicates({:supported_groups, groups}),
    do: reject_duplicates(groups, :duplicate_supported_group)

  defp require_ordered_subset(key_shares, supported_groups) do
    if ordered_subset?(key_shares, supported_groups) do
      :ok
    else
      {:error, {:key_share_not_ordered_subset, key_shares}}
    end
  end

  defp ordered_subset?([], _supported_groups), do: true

  defp ordered_subset?([key_share | key_shares], supported_groups) do
    case Enum.split_while(supported_groups, &(&1 != key_share)) do
      {_before, []} -> false
      {_before, [_matched | remaining]} -> ordered_subset?(key_shares, remaining)
    end
  end

  defp reject_duplicates(values, error_tag) do
    values
    |> Enum.reduce_while(MapSet.new(), fn value, seen ->
      if MapSet.member?(seen, value) do
        {:halt, {:error, {error_tag, value}}}
      else
        {:cont, MapSet.put(seen, value)}
      end
    end)
    |> case do
      %MapSet{} -> :ok
      error -> error
    end
  end

  defp require_key_share_sizes(groups, capabilities) do
    case Enum.find(groups, &is_nil(key_share_size(&1, capabilities))) do
      nil -> :ok
      group -> {:error, {:unknown_key_share_size, group}}
    end
  end

  defp validate_extensions_length(extensions, capabilities) do
    extensions
    |> Enum.reduce_while(0, fn extension, total ->
      next_total = total + 4 + extension_payload_length(extension, capabilities)

      if next_total <= 0xFFFF do
        {:cont, next_total}
      else
        {:halt, {:error, {:extensions_length_exceeded, next_total, 0xFFFF}}}
      end
    end)
    |> case do
      total when is_integer(total) -> :ok
      error -> error
    end
  end

  # Dynamic values are bounded again after per-connection materialization.
  defp extension_payload_length({:server_name, :from_connection}, _capabilities), do: 0

  defp extension_payload_length({:supported_groups, groups}, _capabilities),
    do: 2 + 2 * length(groups)

  defp extension_payload_length({:ec_point_formats, formats}, _capabilities),
    do: 1 + length(formats)

  defp extension_payload_length({:signature_algorithms, algorithms}, _capabilities),
    do: 2 + 2 * length(algorithms)

  defp extension_payload_length({:signature_algorithms_cert, algorithms}, _capabilities),
    do: 2 + 2 * length(algorithms)

  defp extension_payload_length({:alpn, protocols}, _capabilities) do
    2 + Enum.reduce(protocols, 0, fn protocol, size -> size + 1 + byte_size(protocol) end)
  end

  defp extension_payload_length({:supported_versions, versions}, _capabilities),
    do: 1 + 2 * length(versions)

  defp extension_payload_length({:psk_key_exchange_modes, modes}, _capabilities),
    do: 1 + length(modes)

  defp extension_payload_length({:key_share, groups}, capabilities) do
    2 + Enum.reduce(groups, 0, &(4 + key_share_size(&1, capabilities) + &2))
  end

  defp extension_payload_length({:pre_shared_key, :deferred}, _capabilities), do: 0
  defp extension_payload_length({:padding, :none}, _capabilities), do: 0
  defp extension_payload_length({:padding, size}, _capabilities) when is_integer(size), do: size

  defp extension_payload_length({:padding, {:fixed, size}}, _capabilities), do: size

  defp extension_payload_length({:raw, _extension_id, payload}, _capabilities),
    do: byte_size(payload)

  defp key_share_size(group, capabilities) do
    capabilities
    |> Map.get(:key_share_sizes, %{})
    |> Map.get(group, Map.get(@known_key_share_sizes, group))
  end

  defp reject_unsupported(advertised, supported, error_tag) do
    supported = MapSet.new(supported)

    case Enum.reject(advertised, &MapSet.member?(supported, &1)) do
      [] -> :ok
      unsupported -> {:error, {error_tag, Enum.uniq(unsupported)}}
    end
  end
end
