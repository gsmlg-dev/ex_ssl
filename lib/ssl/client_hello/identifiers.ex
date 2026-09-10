defmodule SSL.ClientHello.Identifiers do
  @moduledoc false

  @uint16 %{
    cipher_suite: %{
      tls_aes_128_gcm_sha256: 0x1301,
      tls_aes_256_gcm_sha384: 0x1302,
      tls_chacha20_poly1305_sha256: 0x1303
    },
    group: %{secp256r1: 0x0017, x25519: 0x001D},
    signature_algorithm: %{
      ecdsa_secp256r1_sha256: 0x0403,
      rsa_pss_rsae_sha256: 0x0804,
      rsa_pss_rsae_sha384: 0x0805,
      rsa_pss_rsae_sha512: 0x0806
    },
    version: %{tlsv1_3: 0x0304}
  }

  @uint8 %{psk_mode: %{psk_ke: 0, psk_dhe_ke: 1}}

  @spec uint16(atom(), term()) :: {:ok, 0..0xFFFF} | {:error, term()}
  def uint16(_kind, value) when is_integer(value) and value in 0..0xFFFF, do: {:ok, value}

  def uint16(kind, value) do
    case get_in(@uint16, [kind, value]) do
      nil -> {:error, {:unsupported_identifier, kind, value}}
      identifier -> {:ok, identifier}
    end
  end

  @spec uint8(atom(), term()) :: {:ok, 0..0xFF} | {:error, term()}
  def uint8(_kind, value) when is_integer(value) and value in 0..0xFF, do: {:ok, value}

  def uint8(kind, value) do
    case get_in(@uint8, [kind, value]) do
      nil -> {:error, {:unsupported_identifier, kind, value}}
      identifier -> {:ok, identifier}
    end
  end

  @spec key_exchange_group(term()) :: {:ok, :x25519 | :secp256r1} | {:error, term()}
  def key_exchange_group(:x25519), do: {:ok, :x25519}
  def key_exchange_group(0x001D), do: {:ok, :x25519}
  def key_exchange_group(:secp256r1), do: {:ok, :secp256r1}
  def key_exchange_group(0x0017), do: {:ok, :secp256r1}
  def key_exchange_group(group), do: {:error, {:unsupported_key_share_group, group}}
end
