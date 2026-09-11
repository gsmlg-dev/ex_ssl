defmodule SSL.PKIX do
  @moduledoc """
  Pure, bounded certificate decoding, trust normalization, and peer verification.

  Certificate chains are accepted in TLS leaf-first order. Trust sources are
  supplied in memory as a DER list or PEM bundle; this module performs no file,
  network, or operating-system trust lookup.
  """

  alias SSL.PKIX.Certificate
  alias SSL.PKIX.VerifiedPeer

  require Record

  Record.defrecordp(
    :otp_certificate,
    :OTPCertificate,
    Record.extract(:OTPCertificate, from_lib: "public_key/include/OTP-PUB-KEY.hrl")
  )

  Record.defrecordp(
    :otp_tbs_certificate,
    :OTPTBSCertificate,
    Record.extract(:OTPTBSCertificate, from_lib: "public_key/include/OTP-PUB-KEY.hrl")
  )

  Record.defrecordp(
    :certificate_extension,
    :Extension,
    Record.extract(:Extension, from_lib: "public_key/include/OTP-PUB-KEY.hrl")
  )

  @default_max_certificates 128
  @default_max_der_bytes 1_048_576
  @default_max_total_der_bytes 8_388_608
  @default_max_pem_bytes 8_388_608
  @rsa_encryption_oid {1, 2, 840, 113_549, 1, 1, 1}
  @ec_public_key_oid {1, 2, 840, 10_045, 2, 1}
  @subject_alt_name_oid {2, 5, 29, 17}
  @option_keys [
    :max_certificates,
    :max_der_bytes,
    :max_total_der_bytes,
    :max_pem_bytes
  ]

  @type identity :: {:dns_id, binary()} | {:ip, binary() | :inet.ip_address()}
  @type option ::
          {:max_certificates, pos_integer()}
          | {:max_der_bytes, pos_integer()}
          | {:max_total_der_bytes, pos_integer()}
          | {:max_pem_bytes, pos_integer()}
  @type error_reason ::
          :empty_certificate_chain
          | :empty_trust_anchors
          | :hostname_mismatch
          | :malformed_pem
          | {:invalid_input, :certificate_chain | :trust_source | :options}
          | {:invalid_identity, term()}
          | {:invalid_certificate, non_neg_integer()}
          | {:certificate_count_limit_exceeded, non_neg_integer(), pos_integer()}
          | {:certificate_der_limit_exceeded, non_neg_integer(), non_neg_integer(), pos_integer()}
          | {:certificate_total_der_limit_exceeded, non_neg_integer(), pos_integer()}
          | {:pem_limit_exceeded, non_neg_integer(), pos_integer()}
          | {:path_validation_failed, term()}

  @spec decode_chain(term(), [option()]) ::
          {:ok, [Certificate.t()]} | {:error, error_reason()}
  def decode_chain(chain, options \\ []) do
    with {:ok, limits} <- limits(options),
         :ok <- nonempty_list(chain, :certificate_chain),
         {:ok, certificates} <- decode_der_list(chain, limits) do
      {:ok, certificates}
    end
  end

  @spec normalize_trust(term(), [option()]) ::
          {:ok, [Certificate.t()]} | {:error, error_reason()}
  def normalize_trust(source, options \\ []) do
    with {:ok, limits} <- limits(options) do
      normalize_trust_source(source, limits)
    end
  end

  @spec verify(term(), term(), term(), [option()]) ::
          {:ok, VerifiedPeer.t()} | {:error, error_reason()}
  def verify(chain, trust_source, identity, options \\ []) do
    with :ok <- validate_identity(identity),
         {:ok, chain} <- decode_chain(chain, options),
         {:ok, trust_anchors} <- normalize_trust(trust_source, options),
         {:ok, public_key} <- validate_path(chain, trust_anchors),
         [leaf | _] <- chain,
         :ok <- verify_identity(leaf.decoded, identity) do
      {:ok,
       %VerifiedPeer{
         leaf_der: leaf.der,
         leaf: leaf.decoded,
         public_key: public_key
       }}
    end
  end

  defp normalize_trust_source(<<>>, _limits), do: {:error, :empty_trust_anchors}

  defp normalize_trust_source(pem, limits) when is_binary(pem) do
    pem_size = byte_size(pem)

    if pem_size > limits.max_pem_bytes do
      {:error, {:pem_limit_exceeded, pem_size, limits.max_pem_bytes}}
    else
      decode_pem(pem, limits)
    end
  end

  defp normalize_trust_source(source, limits) when is_list(source) do
    with :ok <- nonempty_list(source, :trust_source),
         {:ok, certificates} <- decode_der_list(source, limits) do
      {:ok, certificates}
    end
  end

  defp normalize_trust_source(_source, _limits),
    do: {:error, {:invalid_input, :trust_source}}

  defp decode_pem(pem, limits) do
    case safe_pem_decode(pem) do
      [] ->
        {:error, :malformed_pem}

      entries when is_list(entries) ->
        entries
        |> Enum.reduce_while({:ok, []}, fn
          {:Certificate, der, :not_encrypted}, {:ok, certificates} ->
            {:cont, {:ok, [der | certificates]}}

          _entry, _accumulator ->
            {:halt, {:error, :malformed_pem}}
        end)
        |> case do
          {:ok, ders} -> decode_der_list(Enum.reverse(ders), limits)
          {:error, _reason} = error -> error
        end

      :error ->
        {:error, :malformed_pem}
    end
  end

  defp safe_pem_decode(pem) do
    :public_key.pem_decode(pem)
  catch
    _kind, _reason -> :error
  end

  defp decode_der_list(ders, limits) do
    count = length(ders)

    if count > limits.max_certificates do
      {:error, {:certificate_count_limit_exceeded, count, limits.max_certificates}}
    else
      decode_der_entries(ders, limits)
    end
  end

  defp decode_der_entries(ders, limits) do
    ders
    |> Enum.with_index()
    |> Enum.reduce_while({:ok, [], 0}, fn {der, index}, {:ok, certificates, total} ->
      case decode_der(der, index, total, limits) do
        {:ok, certificate, new_total} ->
          {:cont, {:ok, [certificate | certificates], new_total}}

        {:error, _reason} = error ->
          {:halt, error}
      end
    end)
    |> case do
      {:ok, certificates, _total} -> {:ok, Enum.reverse(certificates)}
      {:error, _reason} = error -> error
    end
  end

  defp decode_der(der, index, total, limits) when is_binary(der) do
    der_size = byte_size(der)
    new_total = total + der_size

    cond do
      der_size > limits.max_der_bytes ->
        {:error, {:certificate_der_limit_exceeded, index, der_size, limits.max_der_bytes}}

      new_total > limits.max_total_der_bytes ->
        {:error, {:certificate_total_der_limit_exceeded, new_total, limits.max_total_der_bytes}}

      true ->
        case safe_decode_cert(der) do
          {:ok, decoded} -> {:ok, %Certificate{der: der, decoded: decoded}, new_total}
          :error -> {:error, {:invalid_certificate, index}}
        end
    end
  end

  defp decode_der(_der, index, _total, _limits),
    do: {:error, {:invalid_certificate, index}}

  defp safe_decode_cert(der) do
    {:ok, :public_key.pkix_decode_cert(der, :otp)}
  catch
    _kind, _reason -> :error
  end

  defp validate_path(chain, trust_anchors) do
    Enum.reduce_while(trust_anchors, {:error, {:path_validation_failed, :unknown_ca}}, fn anchor,
                                                                                          _error ->
      path = otp_path(chain, anchor)

      case safe_path_validation(anchor.der, path) do
        {:ok, public_key} -> {:halt, {:ok, public_key}}
        {:error, reason} -> {:cont, {:error, {:path_validation_failed, reason}}}
      end
    end)
  end

  defp otp_path(chain, anchor) do
    chain
    |> maybe_drop_anchor(anchor.der)
    |> Enum.map(& &1.der)
    |> Enum.reverse()
  end

  defp maybe_drop_anchor(chain, anchor_der) do
    case List.last(chain) do
      %Certificate{der: ^anchor_der} -> Enum.drop(chain, -1)
      _certificate -> chain
    end
  end

  defp safe_path_validation(anchor_der, path) do
    case :public_key.pkix_path_validation(anchor_der, path, []) do
      {:ok, {public_key_info, _policy_tree}} ->
        {:ok, certificate_verify_key(public_key_info)}

      {:error, reason} ->
        {:error, reason}
    end
  catch
    kind, reason -> {:error, {kind, reason}}
  end

  defp certificate_verify_key({@ec_public_key_oid, {:ECPoint, _point} = public_key, parameters}),
    do: {public_key, parameters}

  defp certificate_verify_key(
         {@rsa_encryption_oid, {:RSAPublicKey, _modulus, _exponent} = public_key, _parameters}
       ),
       do: public_key

  defp certificate_verify_key(public_key_info), do: public_key_info

  defp verify_identity(certificate, identity) do
    if san_matches_identity?(subject_alt_names(certificate), identity) do
      :ok
    else
      {:error, :hostname_mismatch}
    end
  end

  defp subject_alt_names(certificate) do
    certificate
    |> otp_certificate(:tbsCertificate)
    |> otp_tbs_certificate(:extensions)
    |> find_subject_alt_name()
  end

  defp find_subject_alt_name(:asn1_NOVALUE), do: []

  defp find_subject_alt_name(extensions) when is_list(extensions) do
    Enum.find_value(extensions, [], fn extension ->
      if certificate_extension(extension, :extnID) == @subject_alt_name_oid do
        certificate_extension(extension, :extnValue)
      end
    end)
  end

  defp find_subject_alt_name(_extensions), do: []

  defp san_matches_identity?(names, {:dns_id, reference}) do
    Enum.any?(names, fn
      {:dNSName, name} -> dns_name_matches?(name, reference)
      _name -> false
    end)
  end

  defp san_matches_identity?(names, {:ip, reference}) do
    case ip_reference_bytes(reference) do
      {:ok, reference_bytes} ->
        Enum.any?(names, fn
          {:iPAddress, ^reference_bytes} -> true
          _name -> false
        end)

      :error ->
        false
    end
  end

  defp dns_name_matches?(name, reference) when is_list(name),
    do: dns_name_matches?(List.to_string(name), reference)

  defp dns_name_matches?(name, reference) when is_binary(name) and is_binary(reference) do
    presented_labels = name |> String.downcase() |> String.split(".")
    reference_labels = reference |> String.downcase() |> String.split(".")

    case {presented_labels, reference_labels} do
      {["*" | presented_suffix], [_reference_label | reference_suffix]}
      when presented_suffix != [] ->
        presented_suffix == reference_suffix

      {presented, reference_labels} ->
        "*" not in presented and presented == reference_labels
    end
  end

  defp dns_name_matches?(_name, _reference), do: false

  defp ip_reference_bytes(reference) when is_binary(reference) do
    case :inet.parse_address(String.to_charlist(reference)) do
      {:ok, address} -> ip_reference_bytes(address)
      {:error, _reason} -> :error
    end
  end

  defp ip_reference_bytes({a, b, c, d})
       when a in 0..255 and b in 0..255 and c in 0..255 and d in 0..255,
       do: {:ok, <<a, b, c, d>>}

  defp ip_reference_bytes({a, b, c, d, e, f, g, h})
       when a in 0..65_535 and b in 0..65_535 and c in 0..65_535 and d in 0..65_535 and
              e in 0..65_535 and f in 0..65_535 and g in 0..65_535 and h in 0..65_535,
       do: {:ok, <<a::16, b::16, c::16, d::16, e::16, f::16, g::16, h::16>>}

  defp ip_reference_bytes(_reference), do: :error

  defp validate_identity({:dns_id, hostname})
       when is_binary(hostname) and byte_size(hostname) > 0 do
    if String.valid?(hostname), do: :ok, else: {:error, {:invalid_identity, {:dns_id, hostname}}}
  end

  defp validate_identity({:ip, address}) when is_binary(address) and byte_size(address) > 0 do
    if String.valid?(address), do: :ok, else: {:error, {:invalid_identity, {:ip, address}}}
  end

  defp validate_identity({:ip, {a, b, c, d}})
       when a in 0..255 and b in 0..255 and c in 0..255 and d in 0..255,
       do: :ok

  defp validate_identity({:ip, {a, b, c, d, e, f, g, h}})
       when a in 0..65_535 and b in 0..65_535 and c in 0..65_535 and d in 0..65_535 and
              e in 0..65_535 and f in 0..65_535 and g in 0..65_535 and h in 0..65_535,
       do: :ok

  defp validate_identity(identity), do: {:error, {:invalid_identity, identity}}

  defp nonempty_list([], :certificate_chain), do: {:error, :empty_certificate_chain}
  defp nonempty_list([], :trust_source), do: {:error, :empty_trust_anchors}
  defp nonempty_list([_value | rest], field), do: proper_list_tail(rest, field)
  defp nonempty_list(_value, field), do: {:error, {:invalid_input, field}}

  defp proper_list_tail([], _field), do: :ok
  defp proper_list_tail([_value | rest], field), do: proper_list_tail(rest, field)
  defp proper_list_tail(_tail, field), do: {:error, {:invalid_input, field}}

  defp limits(options) when is_list(options) do
    if Keyword.keyword?(options) and
         Enum.all?(options, fn {key, value} -> key in @option_keys and valid_limit?(value) end) do
      {:ok,
       %{
         max_certificates: Keyword.get(options, :max_certificates, @default_max_certificates),
         max_der_bytes: Keyword.get(options, :max_der_bytes, @default_max_der_bytes),
         max_total_der_bytes:
           Keyword.get(options, :max_total_der_bytes, @default_max_total_der_bytes),
         max_pem_bytes: Keyword.get(options, :max_pem_bytes, @default_max_pem_bytes)
       }}
    else
      {:error, {:invalid_input, :options}}
    end
  end

  defp limits(_options), do: {:error, {:invalid_input, :options}}

  defp valid_limit?(value), do: is_integer(value) and value > 0
end
