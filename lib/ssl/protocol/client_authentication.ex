defmodule SSL.Protocol.ClientAuthentication do
  @moduledoc false

  alias SSL.ClientIdentity
  alias SSL.Crypto.Signature
  alias SSL.Protocol.{Record, ServerFlight, Transcript}
  alias SSL.Protocol.ServerFlight.CertificateRequest

  @max_record_plaintext 16_384
  @rsa_pss_oid {1, 2, 840, 113_549, 1, 1, 10}
  @ecdsa_sha256_oid {1, 2, 840, 10_045, 4, 3, 2}
  @ecdsa_sha384_oid {1, 2, 840, 10_045, 4, 3, 3}
  @ed25519_oid {1, 3, 101, 112}
  @hash_oids %{
    {2, 16, 840, 1, 101, 3, 4, 2, 1} => {0x0804, 0x0809},
    {2, 16, 840, 1, 101, 3, 4, 2, 2} => {0x0805, 0x080A},
    {2, 16, 840, 1, 101, 3, 4, 2, 3} => {0x0806, 0x080B}
  }
  @mgf1_oid {1, 2, 840, 113_549, 1, 1, 8}
  @key_usage_filter <<6, 3, 85, 29, 15>>
  @extended_key_usage_filter <<6, 3, 85, 29, 37>>

  @spec emit(CertificateRequest.t() | nil, ClientIdentity.t() | nil, Transcript.t(), term()) ::
          {:ok, Transcript.t(), term(), [binary()]} | {:error, term()}
  def emit(nil, _identity, transcript, state), do: {:ok, transcript, state, []}

  def emit(%CertificateRequest{} = request, identity, transcript, state) do
    with {:ok, selection} <- select(request, identity),
         {:ok, certificate} <-
           ServerFlight.encode_client_certificate(request.request_context, chain(selection)),
         {:ok, certificate_records, state} <- encrypt_message(state, certificate),
         transcript = Transcript.append(transcript, certificate),
         {:ok, transcript, state, verify_records} <-
           maybe_certificate_verify(selection, transcript, state) do
      {:ok, transcript, state, certificate_records ++ verify_records}
    end
  end

  def emit(_, _, _, _), do: {:error, :invalid_client_authentication}

  @spec select(CertificateRequest.t(), ClientIdentity.t() | nil) ::
          {:ok, nil | {ClientIdentity.t(), non_neg_integer()}} | {:error, term()}
  def select(%CertificateRequest{}, nil), do: {:ok, nil}

  def select(%CertificateRequest{extensions: extensions}, %ClientIdentity{} = identity) do
    requested = extension(extensions, :signature_algorithms, [])
    certificate_policy = extension(extensions, :signature_algorithms_cert, requested)
    authorities = extension(extensions, :certificate_authorities, [])
    oid_filters = extension(extensions, :oid_filters, [])

    cond do
      not oid_filters_compatible?(oid_filters) ->
        # Matching recognized extension values is outside this initial subset.
        {:ok, nil}

      not digital_signature_key_usage?(hd(identity.chain)) ->
        {:ok, nil}

      authorities != [] and not authority_matches?(identity.chain, authorities) ->
        {:ok, nil}

      not certificate_policy_matches?(identity.chain, certificate_policy) ->
        {:ok, nil}

      true ->
        case Enum.find(requested, &(&1 in identity.signature_schemes)) do
          nil -> {:ok, nil}
          scheme -> {:ok, {identity, scheme}}
        end
    end
  end

  def select(_, _), do: {:error, :invalid_client_authentication}

  defp extension(extensions, name, default) do
    case List.keyfind(extensions, name, 0) do
      {^name, value} -> value
      _ -> default
    end
  end

  defp chain(nil), do: []
  defp chain({identity, _scheme}), do: identity.chain

  defp oid_filters_compatible?(filters) do
    Enum.all?(filters, fn
      {oid, _values} when oid in [@key_usage_filter, @extended_key_usage_filter] -> false
      {_oid, _values} -> true
    end)
  end

  defp digital_signature_key_usage?(der) do
    extensions = der |> :public_key.pkix_decode_cert(:otp) |> elem(1) |> elem(10)

    key_usage =
      case extensions do
        :asn1_NOVALUE ->
          nil

        entries when is_list(entries) ->
          Enum.find(entries, fn
            {:Extension, {2, 5, 29, 15}, _, _} -> true
            _ -> false
          end)
      end

    case key_usage do
      nil ->
        true

      {:Extension, {2, 5, 29, 15}, _, usages} when is_list(usages) ->
        :digitalSignature in usages

      _ ->
        false
    end
  catch
    _, _ -> false
  end

  defp maybe_certificate_verify(nil, transcript, state), do: {:ok, transcript, state, []}

  defp maybe_certificate_verify({identity, scheme}, transcript, state) do
    with {:ok, signature} <-
           Signature.sign_client(
             scheme,
             identity.private_key,
             transcript.hash,
             Transcript.digest(transcript)
           ),
         {:ok, encoded} <- ServerFlight.encode_client_certificate_verify(scheme, signature),
         {:ok, records, next_state} <- encrypt_message(state, encoded) do
      {:ok, Transcript.append(transcript, encoded), next_state, records}
    end
  end

  defp encrypt_message(state, bytes), do: encrypt_chunks(state, bytes, [])

  defp encrypt_chunks(state, <<>>, records), do: {:ok, Enum.reverse(records), state}

  defp encrypt_chunks(state, bytes, records) do
    size = min(byte_size(bytes), @max_record_plaintext)
    <<chunk::binary-size(^size), rest::binary>> = bytes

    case Record.encrypt(state, :handshake, chunk) do
      {:ok, record, next_state} -> encrypt_chunks(next_state, rest, [record | records])
      {:error, reason} -> {:error, reason}
    end
  end

  defp authority_matches?(chain, authorities) do
    normalized =
      Enum.map(authorities, fn der ->
        der |> then(&:public_key.der_decode(:Name, &1)) |> :public_key.pkix_normalize_name()
      end)

    Enum.any?(chain, fn der ->
      issuer = der |> :public_key.pkix_decode_cert(:otp) |> elem(1) |> elem(4)
      :public_key.pkix_normalize_name(issuer) in normalized
    end)
  catch
    _, _ -> false
  end

  defp certificate_policy_matches?(chain, accepted) do
    Enum.all?(Enum.with_index(chain), fn {der, index} ->
      if :public_key.pkix_is_self_signed(der) do
        true
      else
        issuer_key =
          case Enum.at(chain, index + 1) do
            nil -> nil
            issuer_der -> certificate_public_key_oid(issuer_der)
          end

        Enum.any?(certificate_signature_schemes(der, issuer_key), &(&1 in accepted))
      end
    end)
  end

  defp certificate_signature_schemes(der, issuer_key) do
    cert = :public_key.pkix_decode_cert(der, :otp)
    {:SignatureAlgorithm, oid, params} = elem(cert, 2)

    case oid do
      {1, 2, 840, 113_549, 1, 1, 11} -> [0x0401]
      {1, 2, 840, 113_549, 1, 1, 12} -> [0x0501]
      {1, 2, 840, 113_549, 1, 1, 13} -> [0x0601]
      @ecdsa_sha256_oid -> ecdsa_certificate_scheme(0x0403, issuer_key)
      @ecdsa_sha384_oid -> ecdsa_certificate_scheme(0x0503, issuer_key)
      @ed25519_oid -> [0x0807]
      @rsa_pss_oid -> pss_certificate_schemes(params, issuer_key)
      _ -> []
    end
  catch
    _, _ -> []
  end

  defp ecdsa_certificate_scheme(scheme, nil), do: [scheme]

  defp ecdsa_certificate_scheme(
         0x0403,
         {{1, 2, 840, 10_045, 2, 1}, {:namedCurve, {1, 2, 840, 10_045, 3, 1, 7}}}
       ),
       do: [0x0403]

  defp ecdsa_certificate_scheme(
         0x0503,
         {{1, 2, 840, 10_045, 2, 1}, {:namedCurve, {1, 3, 132, 0, 34}}}
       ),
       do: [0x0503]

  defp ecdsa_certificate_scheme(_, _), do: []

  defp pss_certificate_schemes(
         {:"RSASSA-PSS-params", {:HashAlgorithm, hash_oid, _},
          {:MaskGenAlgorithm, @mgf1_oid, {:HashAlgorithm, hash_oid, _}}, salt_length, 1},
         issuer_key
       ) do
    case Map.get(@hash_oids, hash_oid) do
      {rsae, pss} ->
        if salt_length == hash_size(hash_oid) do
          case issuer_key do
            nil -> [rsae, pss]
            {@rsa_pss_oid, _} -> [pss]
            _ -> [rsae]
          end
        else
          []
        end

      _ ->
        []
    end
  end

  defp pss_certificate_schemes(_, _), do: []

  defp hash_size({2, 16, 840, 1, 101, 3, 4, 2, 1}), do: 32
  defp hash_size({2, 16, 840, 1, 101, 3, 4, 2, 2}), do: 48
  defp hash_size({2, 16, 840, 1, 101, 3, 4, 2, 3}), do: 64
  defp hash_size(_), do: 0

  defp certificate_public_key_oid(der) do
    der
    |> :public_key.pkix_decode_cert(:otp)
    |> elem(1)
    |> elem(7)
    |> elem(1)
    |> then(fn {:PublicKeyAlgorithm, oid, params} -> {oid, params} end)
  catch
    _, _ -> nil
  end
end
