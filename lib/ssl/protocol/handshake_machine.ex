defmodule SSL.Protocol.HandshakeMachine do
  @moduledoc "Pure TLS client coordinator consuming one complete record at a time."

  alias SSL.ClientHello.{Extension, Serializer}
  alias SSL.ClientHello.Materializer.Materialized
  alias SSL.Crypto.{KeyExchange, KeySchedule, TrafficState}
  alias SSL.Crypto.KeyExchange.KeyPair

  alias SSL.Protocol.{
    ClientOffer,
    HandshakeFramer,
    Record,
    ServerFlight,
    ServerFlightVerifier,
    ServerHello,
    TLS12,
    TLS12Codec,
    Transcript
  }

  alias SSL.Protocol.ServerFlightVerifier.{Incremental, Input}

  @max_handshake_length 1_048_576
  @ccs <<20, 3, 3, 0, 1, 1>>

  @derive {Inspect, except: [:key_pair, :read_state, :write_state, :verifier, :client_identity]}
  defstruct [
    :client_hello,
    :client_ast,
    :key_pair,
    :key_pairs,
    :trust_source,
    :identity,
    :client_identity,
    :offer,
    :server_hello,
    :read_state,
    :write_state,
    :negotiated_protocol,
    :phase,
    :framer,
    :verifier,
    :hrr,
    :hrr_transcript,
    options: []
  ]

  @type event ::
          {:connected, binary() | nil} | {:application_data, binary()} | :closed
  @type t :: %__MODULE__{} | TLS12.t()

  @spec init(Materialized.t(), term(), SSL.PKIX.identity(), keyword()) ::
          {:ok, t(), [binary()]} | {:error, term()}
  def init(materialized, trust_source, identity, opts \\ [])

  def init(%Materialized{} = materialized, trust_source, identity, opts) when is_list(opts) do
    {client_identity, verifier_opts} = Keyword.pop(opts, :client_identity)

    with {:ok, client_hello} <- encoded_client_hello(materialized, verifier_opts),
         {:ok, offer} <- ClientOffer.from_client_hello(client_hello),
         {:ok, key_pairs} <- matching_key_pairs(materialized.key_pairs, offer),
         :ok <- validate_identity(identity) do
      state = %__MODULE__{
        client_hello: client_hello,
        client_ast: materialized.client_hello,
        key_pair: List.first(key_pairs),
        key_pairs: key_pairs,
        trust_source: trust_source,
        identity: identity,
        client_identity: client_identity,
        offer: offer,
        phase: :await_server_hello,
        framer: HandshakeFramer.new(),
        options: verifier_opts
      }

      {:ok, state, plaintext_handshake_records(client_hello)}
    end
  end

  def init(_, _, _, _), do: {:error, {:invalid_input, :handshake_machine}}

  @spec feed(t(), binary()) ::
          {:ok, t(), [binary()], [event()]}
          | {:error, {:fatal_alert, atom(), term()} | {:peer_alert, byte(), byte()}}
  def feed(%TLS12{} = state, record), do: TLS12.feed(state, record)

  def feed(%__MODULE__{phase: phase} = state, @ccs)
      when phase in [:await_server_hello, :await_server_hello_after_retry, :await_server_flight],
      do:
        if(0x0304 in state.offer.offered_versions,
          do: {:ok, state, [], []},
          else: fatal(:unexpected_message, :unexpected_tls12_change_cipher_spec)
        )

  def feed(%__MODULE__{phase: phase}, <<20, _::binary>>)
      when phase in [:await_server_hello, :await_server_hello_after_retry, :await_server_flight],
      do: fatal(:unexpected_message, :invalid_change_cipher_spec)

  def feed(%__MODULE__{phase: phase}, <<21, 3, _minor, 2::16, level, description>>)
      when phase in [:await_server_hello, :await_server_hello_after_retry],
      do: {:error, {:peer_alert, level, description}}

  def feed(
        %__MODULE__{phase: :await_server_flight},
        <<21, 3, _minor, 2::16, _level, _description>>
      ),
      do: fatal(:unexpected_message, :unprotected_alert_after_server_hello)

  def feed(%__MODULE__{phase: phase} = state, record)
      when phase in [:await_server_hello, :await_server_hello_after_retry] and is_binary(record) do
    with {:ok, bytes} <- plaintext_handshake_payload(record),
         {:ok, messages, framer} <-
           HandshakeFramer.feed(state.framer, bytes, max_handshake_length: @max_handshake_length) do
      case {messages, HandshakeFramer.buffered_size(framer)} do
        {[], _buffered} ->
          {:ok, %{state | framer: framer}, [], []}

        {[handshake | _] = handshakes, _buffered} ->
          case TLS12Codec.decode(handshake) do
            {:ok, %{type: :server_hello, cipher_suite: suite}} ->
              if match?(%{version: 0x0303}, SSL.Capabilities.resolve(:cipher_suite, suite)) do
                if 0x0303 in state.offer.offered_versions and suite in state.offer.cipher_suites and
                     state.phase == :await_server_hello do
                  with {:ok, tls12} <-
                         TLS12.new(
                           state.client_hello,
                           state.offer,
                           state.trust_source,
                           state.identity,
                           [client_identity: state.client_identity] ++ state.options
                         ) do
                    TLS12.feed_handshakes(tls12, handshakes, framer)
                  end
                else
                  fatal(:illegal_parameter, :unoffered_tls12_selection)
                end
              else
                accept_initial_tls13(state, handshakes, framer)
              end

            _ ->
              accept_initial_tls13(state, handshakes, framer)
          end

        _other ->
          fatal(:unexpected_message, :invalid_server_hello_flight)
      end
    else
      {:error, {:record_length_exceeded, _, _} = reason} -> fatal(:record_overflow, reason)
      {:error, reason} -> fatal(:decode_error, reason)
    end
  end

  def feed(%__MODULE__{phase: :await_server_flight} = state, record) when is_binary(record) do
    case decrypt_handshake(state.read_state, record) do
      {:ok, :handshake, bytes, read_state} ->
        feed_server_handshake(state, bytes, read_state)

      {:ok, :alert, <<level, description>>, _read_state} ->
        {:error, {:peer_alert, level, description}}

      {:ok, type, _bytes, _read_state} ->
        fatal(:unexpected_message, {:unexpected_inner_content_type, type})

      {:error, reason} ->
        record_error(reason)
    end
  end

  def feed(%__MODULE__{phase: :connected} = state, record)
      when is_binary(record),
      do: feed_connected(state, record)

  def feed(%__MODULE__{phase: :closed}, _record), do: {:error, :closed}

  def feed(_, _), do: fatal(:decode_error, :invalid_record)

  defp accept_initial_tls13(state, [handshake], framer) do
    if HandshakeFramer.buffered_size(framer) == 0 do
      with {:ok, hello} <- decode_server_hello(handshake, state.offer) do
        accept_server_hello(%{state | framer: HandshakeFramer.new()}, hello)
      else
        {:error, reason} -> fatal(:illegal_parameter, reason)
      end
    else
      fatal(:unexpected_message, :invalid_server_hello_flight)
    end
  end

  defp accept_initial_tls13(_, _, _), do: fatal(:unexpected_message, :invalid_server_hello_flight)

  defp feed_server_handshake(state, bytes, read_state) do
    with {:ok, messages, framer} <-
           HandshakeFramer.feed(state.framer, bytes, max_handshake_length: @max_handshake_length),
         verifier = %{state.verifier | server_handshake_state: read_state},
         next = %{state | read_state: read_state, framer: framer, verifier: verifier},
         {:ok, next, outbound, events} <- process_server_messages(next, messages) do
      {:ok, next, outbound, events}
    else
      {:error, {:fatal_alert, _, _}} = error -> error
      {:error, reason} -> fatal(:decode_error, reason)
    end
  end

  @spec encrypt(t(), :application_data | :alert, iodata()) ::
          {:ok, binary(), t()} | {:error, term()}
  def encrypt(%TLS12{} = state, type, data), do: TLS12.encrypt(state, type, data)

  def encrypt(%__MODULE__{phase: :connected, write_state: write} = state, :application_data, data) do
    with {:ok, updates, write} <-
           maybe_update_write(write, TrafficState.key_update_required?(write)),
         {:ok, record, next} <- encrypt_record(state, write, :application_data, data) do
      {:ok, IO.iodata_to_binary([updates, record]), next}
    else
      {:error, {:fatal_alert, _, _}} = error -> error
      {:error, reason} -> fatal(:internal_error, reason)
    end
  end

  def encrypt(%__MODULE__{phase: :closed, write_state: write} = state, :alert, data)
      when not is_nil(write),
      do: encrypt_record(state, write, :alert, data)

  def encrypt(%__MODULE__{write_state: write} = state, :alert, data) when not is_nil(write),
    do: encrypt_record(state, write, :alert, data)

  def encrypt(%__MODULE__{} = state, :alert, data) do
    with {:ok, bytes} <- iodata(data), true <- byte_size(bytes) == 2 do
      {:ok, <<21, 3, 3, 2::16, bytes::binary>>, state}
    else
      false -> {:error, :invalid_alert}
      {:error, _} = error -> error
    end
  end

  def encrypt(_, _, _), do: {:error, :not_connected}

  defp accept_server_hello(state, %ServerHello{kind: :hello_retry_request} = hrr) do
    if state.phase == :await_server_hello_after_retry do
      fatal(:unexpected_message, :second_hello_retry_request)
    else
      with {:ok, ast, key_pair} <- retry_client_hello(state.client_ast, state.key_pair, hrr),
           {:ok, encoded} <- Serializer.encode(ast),
           {:ok, offer} <- ClientOffer.from_client_hello(encoded),
           {:ok, _suite, hash} <- suite(hrr.cipher_suite) do
        transcript =
          Transcript.new(hash)
          |> Transcript.append(state.client_hello)
          |> Transcript.apply_hello_retry_request_rewrite()
          |> Transcript.append(hrr.encoded)
          |> Transcript.append(encoded)

        {:ok,
         %{
           state
           | client_ast: ast,
             client_hello: encoded,
             key_pair: key_pair,
             key_pairs: retry_key_pairs(state.key_pairs, hrr, key_pair),
             offer: offer,
             phase: :await_server_hello_after_retry,
             hrr: hrr,
             hrr_transcript: transcript
         }, plaintext_handshake_records(encoded), []}
      else
        {:error, reason} -> fatal(:illegal_parameter, reason)
      end
    end
  end

  defp accept_server_hello(state, %ServerHello{kind: :server_hello} = hello) do
    with :ok <- validate_hrr_selection(state.hrr, hello),
         {:ok, key_pair} <- selected_key_pair(state.key_pairs, state.key_pair, hello),
         input = %Input{
           client_hello: state.client_hello,
           server_hello: hello,
           client_key_pair: key_pair,
           records: [],
           trust_source: state.trust_source,
           identity: state.identity,
           client_identity: state.client_identity
         },
         {:ok, %Incremental{} = verifier} <-
           start_verifier(input, verifier_options(state.options), state.hrr_transcript) do
      {:ok,
       %{
         state
         | server_hello: hello,
           key_pair: key_pair,
           read_state: verifier.secrets.server_handshake_state,
           write_state: verifier.secrets.client_handshake_state,
           verifier: verifier,
           phase: :await_server_flight
       }, [], []}
    end
  end

  defp process_server_messages(state, messages) do
    Enum.reduce_while(messages, {:ok, state, [], []}, fn encoded, {:ok, current, out, events} ->
      if current.phase == :connected do
        {:halt, fatal(:unexpected_message, :trailing_handshake_after_finished)}
      else
        case ServerFlightVerifier.process_message(current.verifier, encoded) do
          {:ok, verifier} ->
            {:cont, {:ok, %{current | verifier: verifier}, out, events}}

          {:connected, result, records} ->
            connected = %{
              current
              | phase: :connected,
                verifier: nil,
                key_pair: nil,
                client_identity: nil,
                hrr_transcript: nil,
                read_state: result.server_application_state,
                write_state: result.client_application_state,
                negotiated_protocol: result.negotiated_protocol
            }

            {:cont,
             {:ok, connected, out ++ records,
              events ++ [{:connected, result.negotiated_protocol}]}}

          {:error, _} = error ->
            {:halt, error}
        end
      end
    end)
    |> reject_partial_after_finished()
  end

  defp reject_partial_after_finished({:ok, %{phase: :connected, framer: framer}, _, _} = result) do
    if HandshakeFramer.buffered_size(framer) == 0 do
      {:ok, state, records, events} = result
      {:ok, %{state | framer: HandshakeFramer.new()}, records, events}
    else
      fatal(:decode_error, :incomplete_handshake_after_finished)
    end
  end

  defp reject_partial_after_finished(result), do: result

  defp feed_connected(state, record) do
    case Record.decrypt(state.read_state, record) do
      {:ok, :application_data, data, read} ->
        if HandshakeFramer.buffered_size(state.framer) == 0,
          do: {:ok, %{state | read_state: read}, [], [{:application_data, data}]},
          else: fatal(:unexpected_message, :interleaved_post_handshake_record)

      {:ok, :alert, <<1, 0>>, read} ->
        {:ok, %{state | read_state: read, phase: :closed}, [], [:closed]}

      {:ok, :alert, <<level, description>>, _read} ->
        {:error, {:peer_alert, level, description}}

      {:ok, :handshake, bytes, read} ->
        with {:ok, messages, framer} <-
               HandshakeFramer.feed(state.framer, bytes,
                 max_handshake_length: @max_handshake_length
               ),
             :ok <- validate_post_handshake_epoch(messages, framer),
             {:ok, next, records} <-
               process_post_handshake(
                 %{state | read_state: read, framer: framer},
                 messages
               ) do
          {:ok, next, records, []}
        else
          {:error, {:fatal_alert, _, _}} = error -> error
          {:error, reason} -> fatal(:decode_error, reason)
        end

      {:ok, type, _data, _read} ->
        fatal(:unexpected_message, {:unexpected_inner_content_type, type})

      {:error, reason} ->
        record_error(reason)
    end
  end

  defp process_post_handshake(state, messages) do
    Enum.reduce_while(messages, {:ok, state, []}, fn
      # RFC 9846 §4.7.1: no resumption support means no ticket semantic decoding.
      # HandshakeFramer has already checked completeness and the global size bound.
      <<4, _length::24, _body::binary>>, result ->
        {:cont, result}

      message, {:ok, current, out} ->
        case ServerFlight.decode(message, hash: hash_for(current.write_state)) do
          {:ok, %ServerFlight.KeyUpdate{request_update: request?}, <<>>} ->
            case apply_key_update(current, request?) do
              {:ok, next, records} -> {:cont, {:ok, next, out ++ records}}
              {:error, _} = error -> {:halt, error}
            end

          {:ok, decoded, <<>>} ->
            {:halt, fatal(:unexpected_message, {:unsupported_post_handshake, decoded.__struct__})}

          {:error, reason} ->
            {:halt, fatal(:unexpected_message, reason)}
        end
    end)
  end

  defp validate_post_handshake_epoch(messages, framer) do
    key_update_index = Enum.find_index(messages, &match?(<<24, _::binary>>, &1))

    cond do
      is_nil(key_update_index) -> :ok
      key_update_index != length(messages) - 1 -> {:error, :trailing_message_after_key_update}
      HandshakeFramer.buffered_size(framer) != 0 -> {:error, :partial_message_after_key_update}
      true -> :ok
    end
  end

  # A reciprocal update is encrypted with the old write key before switching epochs.
  defp apply_key_update(state, request?) do
    with {:ok, read} <- update_traffic_state(state.read_state),
         {:ok, records, write} <- maybe_update_write(state.write_state, request?) do
      {:ok, %{state | read_state: read, write_state: write}, records}
    end
  end

  defp maybe_update_write(write, false), do: {:ok, [], write}

  defp maybe_update_write(write, true) do
    with true <- TrafficState.may_update_write?(write),
         {:ok, encoded} <- ServerFlight.encode_key_update(false),
         # Compute the candidate before encryption so derivation failure cannot
         # consume the last old-key operation. Install it only after protecting
         # KeyUpdate with the old key; the returned wire order is unchanged.
         {:ok, updated} <- update_traffic_state(write),
         {:ok, record, _advanced_old} <- Record.encrypt(write, :handshake, encoded) do
      {:ok, [record], updated}
    else
      false -> fatal(:internal_error, :generation_exhausted)
      {:error, reason} -> fatal(:internal_error, reason)
    end
  end

  defp update_traffic_state(state) do
    with {:ok, secret} <- KeySchedule.traffic_update(hash_for(state), state.secret),
         {:ok, next} <- KeySchedule.traffic_state(state.cipher_suite, secret) do
      {:ok, %{next | generation: state.generation + 1}}
    end
  end

  defp retry_client_hello(ast, current_pair, hrr) do
    selected =
      Enum.find_value(hrr.extensions, fn
        {:selected_group, group} -> group
        _ -> nil
      end)

    cookie =
      Enum.find_value(hrr.extensions, fn
        {:cookie, value} -> value
        _ -> nil
      end)

    with {:ok, pair} <- retry_key_pair(selected, current_pair),
         {:ok, extensions} <- retry_extensions(ast.extensions, selected, pair, cookie) do
      {:ok, %{ast | extensions: extensions}, pair}
    end
  end

  defp retry_key_pair(nil, pair), do: {:ok, pair}

  defp retry_key_pair(group, _pair) do
    case SSL.Capabilities.resolve(:group, group) do
      %{name: name} -> KeyExchange.generate(name)
      nil -> {:error, {:unsupported_selected_group, group}}
    end
  end

  defp retry_key_pairs(key_pairs, hrr, pair) do
    if Enum.any?(hrr.extensions, &match?({:selected_group, _}, &1)),
      do: [pair],
      else: key_pairs
  end

  defp retry_extensions(extensions, selected, pair, cookie) do
    with {:ok, key_share} <- retry_key_share_extension(selected, pair),
         {:ok, cookie_extension} <- retry_cookie_extension(cookie) do
      replaced =
        extensions
        |> Enum.map(fn
          {51, _} when not is_nil(key_share) -> key_share
          {42, _} -> nil
          extension -> extension
        end)
        |> Enum.reject(&is_nil/1)

      {:ok, insert_cookie(replaced, cookie_extension)}
    end
  end

  defp retry_key_share_extension(nil, _pair), do: {:ok, nil}

  defp retry_key_share_extension(_selected, pair),
    do: Extension.encode({:key_share, [{group_id(pair.group), pair.public_key}]})

  defp retry_cookie_extension(nil), do: {:ok, nil}

  defp retry_cookie_extension(cookie) when byte_size(cookie) <= 65_533,
    do: {:ok, {44, <<byte_size(cookie)::16, cookie::binary>>}}

  defp insert_cookie(extensions, nil), do: extensions

  defp insert_cookie(extensions, cookie) do
    {before_psk, psk} = Enum.split_while(extensions, &(elem(&1, 0) != 41))
    before_psk ++ [cookie] ++ psk
  end

  defp encoded_client_hello(%Materialized{client_hello: ast}, opts) do
    case Keyword.fetch(opts, :encoded_client_hello) do
      {:ok, encoded} when is_binary(encoded) -> {:ok, encoded}
      :error -> Serializer.encode(ast)
      {:ok, _} -> {:error, :invalid_encoded_client_hello}
    end
  end

  defp matching_key_pairs(key_pairs, offer) when is_list(key_pairs) do
    matching =
      Enum.filter(key_pairs, fn
        %KeyPair{group: group, public_key: public} ->
          Enum.any?(
            offer.key_shares,
            &(&1.group == group_id(group) and :crypto.hash_equals(&1.key_exchange, public))
          )

        _ ->
          false
      end)

    cond do
      matching == [] and offer.key_shares == [] and 0x0303 in offer.offered_versions and
        0x0304 not in offer.offered_versions and key_pairs == [] ->
        {:ok, []}

      matching == [] ->
        {:error, :no_matching_client_key_share}

      true ->
        Enum.reduce_while(matching, {:ok, []}, fn pair, {:ok, valid} ->
          case KeyExchange.validate_key_pair(pair) do
            :ok -> {:cont, {:ok, [pair | valid]}}
            {:error, _} = error -> {:halt, error}
          end
        end)
        |> case do
          {:ok, valid} -> {:ok, Enum.reverse(valid)}
          error -> error
        end
    end
  end

  defp matching_key_pairs(_, _), do: {:error, :invalid_key_pairs}

  defp selected_key_pair(key_pairs, fallback, hello) do
    selected_group =
      Enum.find_value(hello.extensions, fn
        {:key_share, %{group: group}} -> group
        _ -> nil
      end)

    case Enum.find(key_pairs || [], &(group_id(&1.group) == selected_group)) do
      %KeyPair{} = pair ->
        {:ok, pair}

      nil ->
        if group_id(fallback.group) == selected_group,
          do: {:ok, fallback},
          else: {:error, {:missing_key_pair_for_selected_group, selected_group}}
    end
  end

  defp validate_hrr_selection(nil, _hello), do: :ok

  defp validate_hrr_selection(hrr, hello) do
    selected_group =
      Enum.find_value(hrr.extensions, fn
        {:selected_group, group} -> group
        _ -> nil
      end)

    final_group =
      Enum.find_value(hello.extensions, fn
        {:key_share, %{group: group}} -> group
        _ -> nil
      end)

    cond do
      hello.cipher_suite != hrr.cipher_suite ->
        {:error, :hello_retry_request_cipher_changed}

      not is_nil(selected_group) and final_group != selected_group ->
        {:error, :hello_retry_request_group_changed}

      true ->
        :ok
    end
  end

  defp plaintext_handshake_payload(<<22, 3, 3, length::16, bytes::binary-size(length)>>),
    do:
      if(length <= 16_384,
        do: {:ok, bytes},
        else: {:error, {:record_length_exceeded, length, 16_384}}
      )

  defp plaintext_handshake_payload(_), do: {:error, :expected_plaintext_handshake_record}

  defp plaintext_handshake_records(handshake), do: plaintext_handshake_records(handshake, [])
  defp plaintext_handshake_records(<<>>, records), do: Enum.reverse(records)

  defp plaintext_handshake_records(bytes, records) do
    size = min(byte_size(bytes), 16_384)
    <<chunk::binary-size(^size), rest::binary>> = bytes
    plaintext_handshake_records(rest, [plaintext_handshake_record(chunk) | records])
  end

  defp plaintext_handshake_record(chunk),
    do: <<22, 3, 3, byte_size(chunk)::16, chunk::binary>>

  defp decode_server_hello(encoded, offer) do
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
      {:ok, %ServerHello{} = hello, <<>>} -> {:ok, hello}
      {:ok, _, remainder} -> {:error, {:trailing_server_hello, byte_size(remainder)}}
      other -> {:error, other}
    end
  end

  defp decrypt_handshake(read, record) do
    case Record.decrypt(read, record) do
      {:ok, type, bytes, next} -> {:ok, type, bytes, next}
      {:error, reason} -> {:error, reason}
    end
  end

  defp encrypt_record(state, write, type, data) do
    with {:ok, bytes} <- iodata(data),
         {:ok, record, next} <- Record.encrypt(write, type, bytes) do
      {:ok, record, %{state | write_state: next}}
    end
  end

  defp iodata(data) do
    {:ok, IO.iodata_to_binary(data)}
  rescue
    ArgumentError -> {:error, :invalid_iodata}
  end

  defp verifier_options(options),
    do:
      Keyword.take(options, [
        :customize_hostname_check,
        :depth,
        :max_handshake_length,
        :max_certificate_count,
        :max_total_certificate_bytes,
        :max_certificate_bytes,
        :max_extension_bytes,
        :max_signature_bytes
      ])

  defp start_verifier(input, options, nil),
    do: ServerFlightVerifier.start_incremental(input, options)

  defp start_verifier(input, options, transcript),
    do: ServerFlightVerifier.start_incremental(input, options, transcript)

  defp suite(value) do
    case SSL.Capabilities.resolve(:cipher_suite, value) do
      %{version: 0x0304, name: name, hash: hash} -> {:ok, name, hash}
      _ -> {:error, {:unsupported_cipher_suite, value}}
    end
  end

  defp hash_for(%{cipher_suite: suite}), do: SSL.Capabilities.resolve(:cipher_suite, suite).hash
  defp group_id(group), do: SSL.Capabilities.resolve(:group, group).id

  defp validate_identity({:dns_id, name}) when is_binary(name), do: :ok
  defp validate_identity({:ip, _}), do: :ok
  defp validate_identity(_), do: {:error, :invalid_identity}

  defp record_error(reason) when reason in [:authentication_failed, :decryption_failed],
    do: fatal(:bad_record_mac, reason)

  defp record_error({:record_length_exceeded, _, _} = reason), do: fatal(:record_overflow, reason)
  defp record_error(reason), do: fatal(:decode_error, reason)
  defp fatal(alert, reason), do: {:error, {:fatal_alert, alert, reason}}
end
