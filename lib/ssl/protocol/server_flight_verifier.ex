defmodule SSL.Protocol.ServerFlightVerifier do
  @moduledoc """
  Pure verification of a normal TLS 1.3 encrypted server handshake flight.

  This module recommends fatal alerts but does not send them. HelloRetryRequest,
  sockets, connection state, and post-handshake messages remain outside this
  bounded in-memory verifier.
  """

  alias SSL.Crypto.{KeyExchange, KeySchedule, Signature}
  alias SSL.Crypto.Finished, as: CryptoFinished
  alias SSL.Crypto.KeyExchange.KeyPair
  alias SSL.PKIX

  alias SSL.Protocol.{
    ClientOffer,
    HandshakeFramer,
    Record,
    ServerFlight,
    ServerHello,
    Transcript
  }

  alias SSL.Protocol.ServerFlight.{
    Certificate,
    CertificateVerify,
    EncryptedExtensions
  }

  alias SSL.Protocol.ServerFlight.Finished, as: ServerFinished

  defmodule Input do
    @moduledoc """
    Exact public handshake inputs and fresh per-connection client key material.
    """

    alias SSL.Crypto.KeyExchange.KeyPair
    alias SSL.Protocol.ServerHello

    @enforce_keys [
      :client_hello,
      :server_hello,
      :client_key_pair,
      :records,
      :trust_source,
      :identity
    ]
    defstruct @enforce_keys

    @type t :: %__MODULE__{
            client_hello: binary(),
            server_hello: ServerHello.t(),
            client_key_pair: KeyPair.t(),
            records: [binary()],
            trust_source: term(),
            identity: SSL.PKIX.identity()
          }
  end

  defmodule Result do
    @moduledoc """
    Verified peer and traffic epochs ready for later connection orchestration.
    """

    alias SSL.Crypto.TrafficState
    alias SSL.PKIX.VerifiedPeer
    alias SSL.Protocol.Transcript

    @derive {Inspect,
             except: [
               :server_handshake_state,
               :client_handshake_state,
               :client_application_state,
               :server_application_state
             ]}
    @enforce_keys [
      :verified_peer,
      :server_handshake_state,
      :client_handshake_state,
      :client_finished_record,
      :client_application_state,
      :server_application_state,
      :transcript
    ]
    defstruct @enforce_keys

    @type t :: %__MODULE__{
            verified_peer: VerifiedPeer.t(),
            server_handshake_state: TrafficState.t(),
            client_handshake_state: TrafficState.t(),
            client_finished_record: binary(),
            client_application_state: TrafficState.t(),
            server_application_state: TrafficState.t(),
            transcript: Transcript.t()
          }
  end

  @default_max_records 64
  @maximum_handshake_length 1_048_576
  @server_flight_option_keys [
    :max_handshake_length,
    :max_certificate_count,
    :max_total_certificate_bytes,
    :max_certificate_bytes,
    :max_extension_bytes,
    :max_signature_bytes,
    :offered_extension_ids,
    :allowed_signature_schemes
  ]
  @option_keys [:max_records | @server_flight_option_keys]

  @type fatal_alert ::
          :bad_record_mac
          | :record_overflow
          | :unknown_ca
          | :bad_certificate
          | :certificate_unknown
          | :decrypt_error
          | :unexpected_message
          | :unsupported_extension
          | :decode_error
          | :illegal_parameter
          | :internal_error

  @spec verify(term(), keyword()) ::
          {:ok, Result.t()} | {:error, {:fatal_alert, fatal_alert(), term()}}
  def verify(input, options \\ []) do
    case verify_flight(input, options) do
      {:ok, %Result{} = result} -> {:ok, result}
      {:error, {alert, reason}} -> {:error, {:fatal_alert, alert, reason}}
    end
  end

  defp verify_flight(%Input{} = input, options) do
    with {:ok, config} <- validate_options(options),
         {:ok, offer, server_hello} <- validate_input(input),
         {:ok, config} <- bind_offer(config, offer),
         input = %{input | server_hello: server_hello},
         {:ok, suite, hash, peer_public_key} <- negotiate(input, offer),
         {:ok, secrets} <- derive_handshake_secrets(input, suite, hash, peer_public_key),
         {:ok, messages, server_handshake_state} <-
           decrypt_records(input.records, secrets.server_handshake_state, config),
         {:ok, verified_peer, transcript} <-
           verify_messages(messages, input, secrets, config, offer),
         {:ok, result} <-
           finish_client_flight(
             verified_peer,
             transcript,
             secrets,
             server_handshake_state
           ) do
      {:ok, result}
    end
  end

  defp verify_flight(_input, _options),
    do: alert(:decode_error, {:invalid_input, :verifier})

  defp validate_input(%Input{} = input) do
    with {:ok, offer} <- client_offer(input.client_hello),
         {:ok, server_hello} <- reparse_server_hello(input.server_hello, offer),
         :ok <- compare_server_hello(input.server_hello, server_hello),
         :ok <- validate_server_hello_kind(server_hello),
         :ok <- validate_key_pair(input.client_key_pair, offer, server_hello) do
      {:ok, offer, server_hello}
    else
      {:error, {_alert, _reason}} = error -> error
    end
  end

  defp client_offer(encoded) do
    case ClientOffer.from_client_hello(encoded) do
      {:ok, offer} -> {:ok, offer}
      {:error, reason} -> alert(:decode_error, reason)
    end
  end

  defp reparse_server_hello(%ServerHello{encoded: encoded}, offer) do
    expectations = %{
      legacy_session_id: offer.legacy_session_id,
      offered_ciphers: offer.cipher_suites,
      offered_versions: offer.offered_versions,
      offered_groups: offer.supported_groups,
      offered_key_share_groups: Enum.map(offer.key_shares, & &1.group),
      offered_extension_ids: offer.extension_ids,
      offered_psk_key_exchange_modes: offer.psk_key_exchange_modes,
      offered_psk_count: offer.psk_count
    }

    case ServerHello.decode(encoded, expectations) do
      {:ok, %ServerHello{} = server_hello, <<>>} ->
        {:ok, server_hello}

      {:ok, %ServerHello{}, remainder} ->
        alert(:decode_error, {:trailing_server_hello, byte_size(remainder)})

      {:more, bytes} ->
        alert(:decode_error, {:incomplete_server_hello, bytes})

      {:error, reason} ->
        alert(:illegal_parameter, reason)
    end
  end

  defp reparse_server_hello(_server_hello, _offer),
    do: alert(:decode_error, {:invalid_input, :server_hello})

  defp validate_server_hello_kind(%ServerHello{kind: :server_hello}), do: :ok

  defp validate_server_hello_kind(%ServerHello{kind: :hello_retry_request}),
    do: alert(:unexpected_message, {:unsupported, :hello_retry_request})

  defp compare_server_hello(supplied, parsed) do
    fields = [
      :cipher_suite,
      :random,
      :legacy_session_id_echo,
      :legacy_version,
      :compression_method,
      :kind
    ]

    case Enum.find(fields, &(Map.get(supplied, &1) != Map.get(parsed, &1))) do
      nil -> compare_server_hello_extensions(supplied.extensions, parsed.extensions)
      field -> alert(:illegal_parameter, {:server_hello_semantics_mismatch, field})
    end
  end

  defp compare_server_hello_extensions(supplied, parsed) do
    cond do
      not proper_extension_list?(supplied) ->
        alert(:illegal_parameter, :malformed_server_hello_extensions)

      server_extension(supplied, :supported_versions) !=
          server_extension(parsed, :supported_versions) ->
        alert(:illegal_parameter, {:server_hello_semantics_mismatch, :version})

      server_extension(supplied, :key_share) != server_extension(parsed, :key_share) ->
        alert(:illegal_parameter, {:server_hello_semantics_mismatch, :key_share})

      supplied != parsed ->
        alert(:illegal_parameter, {:server_hello_semantics_mismatch, :extensions})

      true ->
        :ok
    end
  end

  defp server_extension(extensions, name) when is_list(extensions),
    do:
      Enum.find(extensions, fn
        {^name, _value} -> true
        _extension -> false
      end)

  defp server_extension(_extensions, _name), do: :malformed

  defp proper_extension_list?([]), do: true
  defp proper_extension_list?([{_name, _value} | rest]), do: proper_extension_list?(rest)
  defp proper_extension_list?(_extensions), do: false

  defp validate_key_pair(%KeyPair{} = key_pair, offer, server_hello) do
    with {:ok, selected_group, _peer_public} <- server_key_share(server_hello.extensions),
         :ok <- key_pair_result(KeyExchange.validate_key_pair(key_pair)),
         :ok <- bind_key_share_group(selected_group, key_pair.group),
         {:ok, offered_public} <- offered_key_share(offer, selected_group),
         true <- :crypto.hash_equals(offered_public, key_pair.public_key) do
      :ok
    else
      false -> alert(:illegal_parameter, :client_key_pair_public_mismatch)
      {:error, {_alert, _reason}} = error -> error
    end
  end

  defp validate_key_pair(_key_pair, _offer, _server_hello),
    do: alert(:illegal_parameter, :invalid_key_pair)

  defp offered_key_share(offer, selected_group) do
    case Enum.find(offer.key_shares, &(&1.group == selected_group)) do
      %{key_exchange: public_key} -> {:ok, public_key}
      nil -> alert(:illegal_parameter, {:client_key_share_not_offered, selected_group})
    end
  end

  defp key_pair_result(:ok), do: :ok
  defp key_pair_result({:error, reason}), do: alert(:illegal_parameter, reason)

  defp negotiate(%Input{server_hello: server_hello, client_key_pair: client_key_pair}, _offer) do
    with {:ok, suite, hash} <- cipher_suite(server_hello.cipher_suite),
         {:ok, group, peer_public_key} <- server_key_share(server_hello.extensions),
         :ok <- bind_key_share_group(group, client_key_pair.group) do
      {:ok, suite, hash, peer_public_key}
    end
  end

  defp cipher_suite(0x1301), do: {:ok, :tls_aes_128_gcm_sha256, :sha256}
  defp cipher_suite(0x1302), do: {:ok, :tls_aes_256_gcm_sha384, :sha384}
  defp cipher_suite(0x1303), do: {:ok, :tls_chacha20_poly1305_sha256, :sha256}

  defp cipher_suite(cipher_suite),
    do: alert(:illegal_parameter, {:unsupported_cipher_suite, cipher_suite})

  defp server_key_share(extensions), do: server_key_share(extensions, nil)

  defp server_key_share([], nil), do: alert(:illegal_parameter, :missing_key_share)
  defp server_key_share([], {group, key_exchange}), do: {:ok, group, key_exchange}

  defp server_key_share([{:supported_versions, 0x0304} | rest], key_share),
    do: server_key_share(rest, key_share)

  defp server_key_share([{:pre_shared_key, _selected_identity} | _rest], _key_share),
    do: alert(:illegal_parameter, {:unsupported, :pre_shared_key})

  defp server_key_share(
         [{:key_share, %{group: group, key_exchange: key_exchange}} | rest],
         nil
       )
       when is_integer(group) and is_binary(key_exchange),
       do: server_key_share(rest, {group, key_exchange})

  defp server_key_share([{:key_share, _key_share} | _rest], nil),
    do: alert(:illegal_parameter, :malformed_key_share)

  defp server_key_share([{:key_share, _key_share} | _rest], {_group, _key_exchange}),
    do: alert(:illegal_parameter, :duplicate_key_share)

  defp server_key_share([_invalid_extension | _rest], _key_share),
    do: alert(:illegal_parameter, :malformed_server_hello_extensions)

  defp server_key_share(_improper_tail, _key_share),
    do: alert(:illegal_parameter, :malformed_server_hello_extensions)

  defp bind_key_share_group(0x001D, :x25519), do: :ok
  defp bind_key_share_group(0x0017, :secp256r1), do: :ok

  defp bind_key_share_group(group, client_group),
    do: alert(:illegal_parameter, {:key_share_group_mismatch, group, client_group})

  defp derive_handshake_secrets(input, suite, hash, peer_public_key) do
    with {:ok, shared_secret} <-
           crypto_result(
             KeyExchange.shared_secret(input.client_key_pair, peer_public_key),
             :illegal_parameter
           ),
         {:ok, early_secret} <- crypto_result(KeySchedule.early_secret(hash, nil)),
         {:ok, handshake_secret} <-
           crypto_result(KeySchedule.handshake_secret(hash, early_secret, shared_secret)),
         transcript =
           Transcript.new(hash)
           |> Transcript.append(input.client_hello)
           |> Transcript.append(input.server_hello.encoded),
         transcript_hash = Transcript.digest(transcript),
         {:ok, client_secret} <-
           crypto_result(
             KeySchedule.client_handshake_traffic_secret(
               hash,
               handshake_secret,
               transcript_hash
             )
           ),
         {:ok, server_secret} <-
           crypto_result(
             KeySchedule.server_handshake_traffic_secret(
               hash,
               handshake_secret,
               transcript_hash
             )
           ),
         {:ok, client_state} <-
           crypto_result(KeySchedule.traffic_state(suite, client_secret)),
         {:ok, server_state} <-
           crypto_result(KeySchedule.traffic_state(suite, server_secret)),
         {:ok, master_secret} <-
           crypto_result(KeySchedule.master_secret(hash, handshake_secret)) do
      {:ok,
       %{
         suite: suite,
         hash: hash,
         transcript: transcript,
         client_handshake_secret: client_secret,
         server_handshake_secret: server_secret,
         client_handshake_state: client_state,
         server_handshake_state: server_state,
         master_secret: master_secret
       }}
    end
  end

  defp decrypt_records(records, state, config) do
    with :ok <- validate_record_count(records, config.max_records) do
      records
      |> Enum.reduce_while({:ok, [], HandshakeFramer.new(), state}, fn
        record, {:ok, messages, framer, current_state} ->
          case decrypt_record(record, current_state, framer, config) do
            {:ok, decoded, next_framer, next_state} ->
              updated_messages = Enum.reverse(decoded, messages)

              if length(updated_messages) > 4 do
                {:halt, alert(:unexpected_message, {:trailing_handshake_messages, 5})}
              else
                {:cont, {:ok, updated_messages, next_framer, next_state}}
              end

            {:error, {_alert, _reason}} = error ->
              {:halt, error}
          end
      end)
      |> complete_handshake_stream()
    end
  end

  defp validate_record_count([], _maximum),
    do: alert(:unexpected_message, :empty_server_flight)

  defp validate_record_count(records, maximum),
    do: validate_record_count(records, maximum, 0)

  defp validate_record_count([], _maximum, _count), do: :ok

  defp validate_record_count([_record | _rest], maximum, maximum),
    do: alert(:decode_error, {:record_count_limit_exceeded, maximum + 1, maximum})

  defp validate_record_count([_record | rest], maximum, count),
    do: validate_record_count(rest, maximum, count + 1)

  defp validate_record_count(_records, _maximum, _count),
    do: alert(:decode_error, {:invalid_input, :records})

  defp decrypt_record(record, state, framer, config) do
    case Record.decrypt(state, record) do
      {:ok, :handshake, plaintext, next_state} ->
        case HandshakeFramer.feed(
               framer,
               plaintext,
               max_handshake_length: config.max_handshake_length
             ) do
          {:ok, decoded, next_framer} -> {:ok, decoded, next_framer, next_state}
          {:error, reason} -> alert(:decode_error, reason)
        end

      {:ok, content_type, _content, _next_state} ->
        alert(:unexpected_message, {:unexpected_inner_content_type, content_type})

      {:error, reason} when reason in [:authentication_failed, :decryption_failed] ->
        alert(:bad_record_mac, reason)

      {:error, {:record_length_exceeded, _length, _maximum} = reason} ->
        alert(:record_overflow, reason)

      {:error, {:inner_plaintext_length_exceeded, _length, _maximum} = reason} ->
        alert(:record_overflow, reason)

      {:error, {:content_length_exceeded, _length, _maximum} = reason} ->
        alert(:record_overflow, reason)

      {:error, {:empty_content, content_type} = reason}
      when content_type in [:handshake, :alert] ->
        alert(:unexpected_message, reason)

      {:error, reason} when reason in [:empty_inner_plaintext, :missing_inner_content_type] ->
        alert(:unexpected_message, reason)

      {:error, reason} ->
        alert(:decode_error, reason)
    end
  end

  defp complete_handshake_stream({:error, {_alert, _reason}} = error), do: error

  defp complete_handshake_stream({:ok, messages, framer, state}) do
    case HandshakeFramer.buffered_size(framer) do
      0 -> {:ok, Enum.reverse(messages), state}
      bytes -> alert(:decode_error, {:incomplete_handshake, bytes})
    end
  end

  defp verify_messages(
         [encrypted_extensions, certificate, certificate_verify, finished],
         input,
         secrets,
         config,
         offer
       ) do
    options = [{:hash, secrets.hash} | config.server_flight_options]

    with {:ok, %EncryptedExtensions{} = encrypted_extensions} <-
           decode_message(encrypted_extensions, EncryptedExtensions, options),
         :ok <- validate_encrypted_extensions(encrypted_extensions, offer),
         transcript = Transcript.append(secrets.transcript, encrypted_extensions.encoded),
         {:ok, %Certificate{} = certificate} <-
           decode_message(certificate, Certificate, options),
         :ok <- validate_certificate_extensions(certificate, offer),
         transcript = Transcript.append(transcript, certificate.encoded),
         {:ok, verified_peer} <- verify_peer(certificate, input),
         {:ok, %CertificateVerify{} = certificate_verify} <-
           decode_message(certificate_verify, CertificateVerify, options),
         :ok <- verify_certificate_signature(certificate_verify, verified_peer, transcript),
         transcript = Transcript.append(transcript, certificate_verify.encoded),
         {:ok, %ServerFinished{} = finished} <-
           decode_message(finished, ServerFinished, options),
         :ok <- verify_server_finished(finished, transcript, secrets),
         transcript = Transcript.append(transcript, finished.encoded) do
      {:ok, verified_peer, transcript}
    end
  end

  defp verify_messages(messages, _input, _secrets, _config, _offer),
    do: alert(:unexpected_message, {:invalid_server_flight_order, message_types(messages)})

  defp decode_message(encoded, expected_module, options) do
    case ServerFlight.decode(encoded, options) do
      {:ok, %{__struct__: ^expected_module} = message, <<>>} ->
        {:ok, message}

      {:ok, message, <<>>} ->
        alert(:unexpected_message, {:expected, expected_module, message.__struct__})

      {:ok, _message, remainder} ->
        alert(:decode_error, {:trailing_handshake_bytes, byte_size(remainder)})

      {:more, bytes} ->
        alert(:decode_error, {:incomplete_handshake_message, bytes})

      {:error, reason} ->
        decode_alert(reason)
    end
  end

  defp validate_encrypted_extensions(%EncryptedExtensions{extensions: extensions}, offer) do
    Enum.reduce_while(extensions, :ok, fn extension, :ok ->
      case validate_encrypted_extension(extension, offer) do
        :ok -> {:cont, :ok}
        {:error, {_alert, _reason}} = error -> {:halt, error}
      end
    end)
  end

  defp validate_encrypted_extension({:early_data}, offer) do
    if 42 in offer.extension_ids do
      alert(:illegal_parameter, {:early_data_not_permitted, :non_psk})
    else
      alert(:unsupported_extension, {:unsolicited_extension, 42})
    end
  end

  defp validate_encrypted_extension({:alpn, protocol}, offer) do
    cond do
      16 not in offer.extension_ids ->
        alert(:unsupported_extension, {:unsolicited_extension, 16})

      protocol not in offer.alpn_protocols ->
        alert(:illegal_parameter, {:alpn_not_offered, protocol})

      true ->
        :ok
    end
  end

  defp validate_encrypted_extension(_extension, _offer), do: :ok

  defp validate_certificate_extensions(%Certificate{entries: entries}, offer) do
    entries
    |> Enum.with_index()
    |> Enum.reduce_while(:ok, fn {entry, index}, :ok ->
      case validate_certificate_entry_extensions(entry.extensions, offer, index) do
        :ok -> {:cont, :ok}
        {:error, {_alert, _reason}} = error -> {:halt, error}
      end
    end)
  end

  defp validate_certificate_entry_extensions(extensions, offer, index) do
    Enum.reduce_while(extensions, :ok, fn extension, :ok ->
      case certificate_extension_id(extension) do
        id when id in [5, 18] ->
          if id in offer.extension_ids do
            {:cont, :ok}
          else
            {:halt,
             alert(:unsupported_extension, {:unsolicited_certificate_extension, id, index})}
          end

        _id ->
          {:cont, :ok}
      end
    end)
  end

  defp certificate_extension_id({:status_request, _response}), do: 5
  defp certificate_extension_id({:signed_certificate_timestamps, _timestamps}), do: 18
  defp certificate_extension_id(_extension), do: nil

  defp decode_alert({:extension_not_offered, id}),
    do: alert(:unsupported_extension, {:unsolicited_extension, id})

  defp decode_alert({:forbidden_extension, context, id}),
    do: alert(:unsupported_extension, {:forbidden_extension, context, id})

  defp decode_alert({:signature_scheme_not_allowed, scheme}),
    do: alert(:illegal_parameter, {:signature_scheme_not_offered, scheme})

  defp decode_alert(reason), do: alert(:decode_error, reason)

  defp verify_peer(%Certificate{entries: entries}, input) do
    chain = Enum.map(entries, & &1.der)

    case PKIX.verify(chain, input.trust_source, input.identity) do
      {:ok, verified_peer} -> {:ok, verified_peer}
      {:error, :hostname_mismatch = reason} -> alert(:certificate_unknown, reason)
      {:error, {:path_validation_failed, _path_reason} = reason} -> alert(:unknown_ca, reason)
      {:error, reason} -> alert(:bad_certificate, reason)
    end
  end

  defp verify_certificate_signature(certificate_verify, verified_peer, transcript) do
    case Signature.verify_server(
           certificate_verify.signature_scheme,
           verified_peer.public_key,
           transcript.hash,
           Transcript.digest(transcript),
           certificate_verify.signature
         ) do
      :ok -> :ok
      {:error, reason} -> alert(:decrypt_error, reason)
    end
  end

  defp verify_server_finished(finished, transcript, secrets) do
    case CryptoFinished.verify_server(
           secrets.hash,
           secrets.server_handshake_secret,
           Transcript.digest(transcript),
           finished.verify_data
         ) do
      :ok -> :ok
      {:error, reason} -> alert(:decrypt_error, reason)
    end
  end

  defp finish_client_flight(verified_peer, transcript, secrets, server_handshake_state) do
    transcript_hash = Transcript.digest(transcript)

    with {:ok, client_application_secret} <-
           crypto_result(
             KeySchedule.client_application_traffic_secret(
               secrets.hash,
               secrets.master_secret,
               transcript_hash
             )
           ),
         {:ok, server_application_secret} <-
           crypto_result(
             KeySchedule.server_application_traffic_secret(
               secrets.hash,
               secrets.master_secret,
               transcript_hash
             )
           ),
         {:ok, client_application_state} <-
           crypto_result(KeySchedule.traffic_state(secrets.suite, client_application_secret)),
         {:ok, server_application_state} <-
           crypto_result(KeySchedule.traffic_state(secrets.suite, server_application_secret)),
         {:ok, client_verify_data} <-
           crypto_result(
             CryptoFinished.client_verify_data(
               secrets.hash,
               secrets.client_handshake_secret,
               transcript_hash
             )
           ),
         {:ok, client_finished} <-
           crypto_result(ServerFlight.encode_finished(client_verify_data, hash: secrets.hash)),
         {:ok, client_finished_record, client_handshake_state} <-
           encrypt_client_finished(secrets.client_handshake_state, client_finished) do
      {:ok,
       %Result{
         verified_peer: verified_peer,
         server_handshake_state: server_handshake_state,
         client_handshake_state: client_handshake_state,
         client_finished_record: client_finished_record,
         client_application_state: client_application_state,
         server_application_state: server_application_state,
         transcript: Transcript.append(transcript, client_finished)
       }}
    end
  end

  defp message_types(messages) do
    Enum.map(messages, fn
      <<type, _rest::binary>> -> type
      _message -> :malformed
    end)
  end

  defp validate_options(options) when is_list(options) do
    if Keyword.keyword?(options) do
      validate_keyword_options(options)
    else
      alert(:decode_error, {:invalid_options, :verifier})
    end
  end

  defp validate_options(_options),
    do: alert(:decode_error, {:invalid_options, :verifier})

  defp validate_keyword_options(options) do
    keys = Keyword.keys(options)

    if length(keys) == length(Enum.uniq(keys)) and Enum.all?(keys, &(&1 in @option_keys)) do
      case Keyword.get(options, :max_records, @default_max_records) do
        maximum when is_integer(maximum) and maximum > 0 ->
          {:ok,
           %{
             max_records: maximum,
             max_handshake_length:
               Keyword.get(options, :max_handshake_length, @maximum_handshake_length),
             server_flight_options: Keyword.drop(options, [:max_records])
           }}

        _maximum ->
          alert(:decode_error, {:invalid_options, :verifier})
      end
    else
      alert(:decode_error, {:invalid_options, :verifier})
    end
  end

  defp bind_offer(config, offer) do
    supplied_extensions = Keyword.fetch(config.server_flight_options, :offered_extension_ids)
    supplied_signatures = Keyword.fetch(config.server_flight_options, :allowed_signature_schemes)

    with :ok <-
           reject_offer_conflict(supplied_extensions, offer.extension_ids, :offered_extension_ids),
         {:ok, allowed_signatures} <-
           signature_policy(supplied_signatures, offer.signature_schemes) do
      options =
        config.server_flight_options
        |> Keyword.put(:offered_extension_ids, offer.extension_ids)
        |> Keyword.put(:allowed_signature_schemes, allowed_signatures)

      {:ok, %{config | server_flight_options: options}}
    end
  end

  defp reject_offer_conflict(:error, _actual, _field), do: :ok
  defp reject_offer_conflict({:ok, actual}, actual, _field), do: :ok

  defp reject_offer_conflict({:ok, _claimed}, _actual, field),
    do: alert(:illegal_parameter, {:offer_override_conflict, field})

  defp signature_policy(:error, offered), do: {:ok, offered}

  defp signature_policy({:ok, policy}, offered) do
    if Enum.all?(policy, &(&1 in offered)) do
      {:ok, policy}
    else
      alert(:illegal_parameter, {:offer_override_conflict, :allowed_signature_schemes})
    end
  end

  defp crypto_result({:ok, value}, _alert), do: {:ok, value}
  defp crypto_result({:error, reason}, alert), do: alert(alert, reason)
  defp crypto_result(result), do: crypto_result(result, :internal_error)

  defp encrypt_client_finished(state, client_finished) do
    case Record.encrypt(state, :handshake, client_finished) do
      {:ok, record, next_state} -> {:ok, record, next_state}
      {:error, reason} -> alert(:internal_error, reason)
    end
  end

  defp alert(alert, reason), do: {:error, {alert, reason}}
end
