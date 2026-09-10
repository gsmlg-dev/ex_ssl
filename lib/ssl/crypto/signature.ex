defmodule SSL.Crypto.Signature do
  @moduledoc """
  TLS 1.3 CertificateVerify signed-content construction and verification.

  This module verifies handshake signatures only. Certificate path and service
  identity validation remain separate PKIX responsibilities.
  """

  @server_context "TLS 1.3, server CertificateVerify"
  @space_prefix :binary.copy(<<0x20>>, 64)
  @secp256r1_oid {1, 2, 840, 10_045, 3, 1, 7}
  @secp384r1_oid {1, 3, 132, 0, 34}

  @type signature_scheme :: 0x0403 | 0x0804 | 0x0805 | 0x0806
  @type error_reason ::
          :unsupported_hash
          | :invalid_certificate_verify
          | :signature_verification_failed
          | :empty_signature
          | :invalid_public_key
          | {:unsupported_signature_scheme, term()}
          | {:invalid_input, :transcript_hash | :signature}
          | {:invalid_transcript_hash_length, pos_integer()}
          | {:key_type_mismatch, :ecdsa | :rsa}
          | {:unsupported_ec_curve, atom() | tuple()}

  @spec server_signed_content(atom(), term()) ::
          {:ok, binary()} | {:error, error_reason()}
  def server_signed_content(hash, transcript_hash) do
    with {:ok, hash_length} <- hash_length(hash),
         :ok <- validate_transcript_hash(transcript_hash, hash_length) do
      {:ok, <<@space_prefix::binary, @server_context::binary, 0, transcript_hash::binary>>}
    end
  end

  @spec verify_server(term(), term(), term(), term()) :: :ok | {:error, error_reason()}
  def verify_server(signature_scheme, public_key, transcript_hash, signature) do
    with {:ok, key_type, hash, verify_options} <- signature_scheme(signature_scheme),
         {:ok, signed_content} <- server_signed_content(hash, transcript_hash),
         :ok <- validate_signature(signature),
         :ok <- validate_public_key(key_type, public_key) do
      verify(signed_content, hash, signature, public_key, verify_options)
    end
  end

  defp signature_scheme(0x0403), do: {:ok, :ecdsa, :sha256, []}

  defp signature_scheme(0x0804),
    do: {:ok, :rsa, :sha256, rsa_pss_options(:sha256, 32)}

  defp signature_scheme(0x0805),
    do: {:ok, :rsa, :sha384, rsa_pss_options(:sha384, 48)}

  defp signature_scheme(0x0806),
    do: {:ok, :rsa, :sha512, rsa_pss_options(:sha512, 64)}

  defp signature_scheme(signature_scheme),
    do: {:error, {:unsupported_signature_scheme, signature_scheme}}

  defp rsa_pss_options(hash, salt_length) do
    [
      {:rsa_padding, :rsa_pkcs1_pss_padding},
      {:rsa_pss_saltlen, salt_length},
      {:rsa_mgf1_md, hash}
    ]
  end

  defp validate_public_key(
         :ecdsa,
         {{:ECPoint, <<4, _coordinates::binary-size(64)>>}, {:namedCurve, @secp256r1_oid}}
       ),
       do: :ok

  defp validate_public_key(:ecdsa, {{:ECPoint, _point}, {:namedCurve, @secp384r1_oid}}),
    do: {:error, {:unsupported_ec_curve, :secp384r1}}

  defp validate_public_key(:ecdsa, {{:ECPoint, _point}, {:namedCurve, oid}}),
    do: {:error, {:unsupported_ec_curve, oid}}

  defp validate_public_key(:ecdsa, {:RSAPublicKey, modulus, exponent})
       when is_integer(modulus) and is_integer(exponent),
       do: {:error, {:key_type_mismatch, :ecdsa}}

  defp validate_public_key(:rsa, {:RSAPublicKey, modulus, exponent})
       when is_integer(modulus) and modulus > 0 and is_integer(exponent) and exponent > 0,
       do: :ok

  defp validate_public_key(:rsa, {{:ECPoint, _point}, {:namedCurve, _oid}}),
    do: {:error, {:key_type_mismatch, :rsa}}

  defp validate_public_key(_key_type, _public_key), do: {:error, :invalid_public_key}

  defp validate_signature(signature) when is_binary(signature) and byte_size(signature) > 0,
    do: :ok

  defp validate_signature(<<>>), do: {:error, :empty_signature}
  defp validate_signature(_signature), do: {:error, {:invalid_input, :signature}}

  defp validate_transcript_hash(transcript_hash, expected_length)
       when is_binary(transcript_hash) and byte_size(transcript_hash) == expected_length,
       do: :ok

  defp validate_transcript_hash(transcript_hash, _expected_length)
       when not is_binary(transcript_hash),
       do: {:error, {:invalid_input, :transcript_hash}}

  defp validate_transcript_hash(_transcript_hash, expected_length),
    do: {:error, {:invalid_transcript_hash_length, expected_length}}

  defp hash_length(:sha256), do: {:ok, 32}
  defp hash_length(:sha384), do: {:ok, 48}
  defp hash_length(:sha512), do: {:ok, 64}
  defp hash_length(_hash), do: {:error, :unsupported_hash}

  defp verify(signed_content, hash, signature, public_key, options) do
    if :public_key.verify(signed_content, hash, signature, public_key, options) do
      :ok
    else
      {:error, :invalid_certificate_verify}
    end
  catch
    :error, _reason -> {:error, :signature_verification_failed}
  end
end
