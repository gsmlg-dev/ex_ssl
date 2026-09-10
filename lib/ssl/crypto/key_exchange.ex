defmodule SSL.Crypto.KeyExchange do
  @moduledoc """
  Fresh ephemeral key generation and shared-secret computation for TLS groups.

  Runtime support is determined by the crypto provider linked to OTP.
  """

  defmodule KeyPair do
    @moduledoc """
    Ephemeral key material for one key exchange.

    Inspection intentionally excludes the private key.
    """

    @type group :: :x25519 | :secp256r1
    @type t :: %__MODULE__{group: group(), public_key: binary(), private_key: binary()}

    @derive {Inspect, except: [:private_key]}
    @enforce_keys [:group, :public_key, :private_key]
    defstruct [:group, :public_key, :private_key]
  end

  alias __MODULE__.KeyPair

  @type group :: KeyPair.group()
  @type error_reason ::
          {:unsupported_group, term()}
          | {:unsupported_capability, group()}
          | {:key_generation_failed, group()}
          | {:invalid_private_key, group()}
          | {:invalid_peer_public_key, group()}
          | :invalid_key_pair

  @spec supported?(term()) :: boolean()
  def supported?(group) when group in [:x25519, :secp256r1] do
    group in :crypto.supports(:curves) and :ecdh in :crypto.supports(:public_keys)
  end

  def supported?(_group), do: false

  @spec generate(term()) :: {:ok, KeyPair.t()} | {:error, error_reason()}
  def generate(group) when group in [:x25519, :secp256r1] do
    if supported?(group) do
      generate_supported(group)
    else
      {:error, {:unsupported_capability, group}}
    end
  end

  def generate(group), do: {:error, {:unsupported_group, group}}

  @spec shared_secret(KeyPair.t(), term()) :: {:ok, binary()} | {:error, error_reason()}
  def shared_secret(%KeyPair{group: group}, _peer_public_key)
      when group not in [:x25519, :secp256r1],
      do: {:error, {:unsupported_group, group}}

  def shared_secret(%KeyPair{group: group, private_key: private_key}, peer_public_key) do
    with true <- supported?(group),
         :ok <- validate_private_key(group, private_key),
         :ok <- validate_peer_public_key(group, peer_public_key) do
      compute_shared_secret(group, peer_public_key, private_key)
    else
      false -> {:error, {:unsupported_capability, group}}
      {:error, _reason} = error -> error
    end
  end

  def shared_secret(_key_pair, _peer_public_key), do: {:error, :invalid_key_pair}

  defp generate_supported(group) do
    {public_key, private_key} = :crypto.generate_key(:ecdh, group)
    {:ok, %KeyPair{group: group, public_key: public_key, private_key: private_key}}
  catch
    :error, {:error, {_file, _line}, _message} ->
      {:error, {:key_generation_failed, group}}

    :error, {:badarg, {_file, _line}, _message} ->
      {:error, {:key_generation_failed, group}}

    :error, :badarg ->
      {:error, {:key_generation_failed, group}}
  end

  defp validate_private_key(group, private_key)
       when is_binary(private_key) and byte_size(private_key) == 32 do
    case :crypto.generate_key(:ecdh, group, private_key) do
      {<<_public_key::binary-size(32)>>, ^private_key} when group == :x25519 ->
        :ok

      {<<4, _coordinates::binary-size(64)>>, ^private_key} when group == :secp256r1 ->
        :ok

      _invalid_key_pair ->
        {:error, {:invalid_private_key, group}}
    end
  catch
    :error, {:error, {_file, _line}, _message} ->
      {:error, {:invalid_private_key, group}}

    :error, {:badarg, {_file, _line}, _message} ->
      {:error, {:invalid_private_key, group}}

    :error, :badarg ->
      {:error, {:invalid_private_key, group}}
  end

  defp validate_private_key(group, _private_key), do: {:error, {:invalid_private_key, group}}

  defp validate_peer_public_key(:x25519, peer_public_key)
       when is_binary(peer_public_key) and byte_size(peer_public_key) == 32,
       do: :ok

  defp validate_peer_public_key(:secp256r1, <<4, _coordinates::binary-size(64)>>), do: :ok

  defp validate_peer_public_key(group, _peer_public_key),
    do: {:error, {:invalid_peer_public_key, group}}

  defp compute_shared_secret(group, peer_public_key, private_key) do
    case :crypto.compute_key(:ecdh, peer_public_key, private_key, group) do
      <<0::256>> when group == :x25519 ->
        {:error, {:invalid_peer_public_key, group}}

      shared_secret ->
        {:ok, shared_secret}
    end
  catch
    :error, {:error, {_file, _line}, _message} ->
      {:error, {:invalid_peer_public_key, group}}

    :error, {:badarg, {_file, _line}, _message} ->
      {:error, {:invalid_peer_public_key, group}}

    :error, :badarg ->
      {:error, {:invalid_peer_public_key, group}}
  end
end
