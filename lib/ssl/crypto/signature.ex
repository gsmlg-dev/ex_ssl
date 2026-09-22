defmodule SSL.Crypto.Signature do
  @moduledoc """
  TLS 1.3 CertificateVerify signed-content construction and verification.

  This module verifies handshake signatures only. Certificate path and service
  identity validation remain separate PKIX responsibilities.
  """

  @server_context "TLS 1.3, server CertificateVerify"
  @space_prefix :binary.copy(<<0x20>>, 64)
  alias SSL.Capabilities
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

  @spec verify_server(term(), term(), atom(), term(), term()) :: :ok | {:error, error_reason()}
  def verify_server(
        signature_scheme,
        public_key,
        transcript_hash_algorithm,
        transcript_digest,
        signature
      ) do
    with {:ok, scheme} <- signature_scheme(signature_scheme),
         {:ok, signed_content} <-
           server_signed_content(transcript_hash_algorithm, transcript_digest),
         :ok <- validate_signature(signature),
         :ok <- validate_public_key(scheme, public_key) do
      verify(signed_content, scheme.hash, signature, public_key, scheme.verify_options)
    end
  end

  defp signature_scheme(value) do
    case Capabilities.signature(value) do
      %{id: ^value} = scheme ->
        if value in Capabilities.identifiers(:signature_algorithm),
          do: {:ok, scheme},
          else: {:error, {:unsupported_signature_scheme, value}}

      _ ->
        {:error, {:unsupported_signature_scheme, value}}
    end
  end

  defp validate_public_key(
         %{key: :ecdsa, curve_oid: oid, public_key_size: size},
         {{:ECPoint, <<4, _coordinates::binary>> = point}, {:namedCurve, oid}}
       )
       when byte_size(point) == size,
       do: :ok

  defp validate_public_key(%{key: :ecdsa}, {{:ECPoint, _point}, {:namedCurve, @secp384r1_oid}}),
    do: {:error, {:unsupported_ec_curve, :secp384r1}}

  defp validate_public_key(%{key: :ecdsa}, {{:ECPoint, _point}, {:namedCurve, oid}}),
    do: {:error, {:unsupported_ec_curve, oid}}

  defp validate_public_key(%{key: :ecdsa}, {:RSAPublicKey, modulus, exponent})
       when is_integer(modulus) and is_integer(exponent),
       do: {:error, {:key_type_mismatch, :ecdsa}}

  defp validate_public_key(%{key: :rsa}, {:RSAPublicKey, modulus, exponent})
       when is_integer(modulus) and modulus > 0 and is_integer(exponent) and exponent > 0,
       do: :ok

  defp validate_public_key(%{key: :rsa}, {{:ECPoint, _point}, {:namedCurve, _oid}}),
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
