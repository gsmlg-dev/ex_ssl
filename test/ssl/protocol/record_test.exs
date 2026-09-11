defmodule SSL.Protocol.RecordTest do
  use ExUnit.Case, async: true
  use ExUnitProperties

  alias SSL.Crypto.AEAD
  alias SSL.Crypto.TrafficState
  alias SSL.Protocol.Record
  alias SSL.Protocol.RecordFramer

  @key Base.decode16!("000102030405060708090A0B0C0D0E0F")
  @iv Base.decode16!("0F0E0D0C0B0A090807060504")
  @record Base.decode16!("17030300194A01B932A3283C6365D9242F72919FC3DC2BE2E1497E268421")

  test "encrypts the independent OpenSSL AES-128-GCM record vector" do
    state = state()

    assert {:ok, @record, %TrafficState{sequence: 1}} =
             Record.encrypt(state, :handshake, "hello", padding_length: 3)

    assert state.sequence == 0
  end

  test "decrypts the independent record vector and advances only returned state" do
    state = state()

    assert {:ok, :handshake, "hello", %TrafficState{sequence: 1}} =
             Record.decrypt(state, @record)

    assert state.sequence == 0
  end

  test "round trips every supported inner content type" do
    for type <- [:handshake, :alert, :application_data] do
      assert {:ok, record, write_state} = Record.encrypt(state(), type, <<1, 2, 0>>, [])
      assert write_state.sequence == 1

      assert {:ok, ^type, <<1, 2, 0>>, read_state} = Record.decrypt(state(), record)
      assert read_state.sequence == 1
    end
  end

  test "uses application_data and TLS 1.2 legacy version in the exact AAD header" do
    assert {:ok, <<23, 3, 3, length::16, body::binary>>, _state} =
             Record.encrypt(state(), :alert, <<2, 40>>, [])

    assert length == byte_size(body)
    assert length == 19
  end

  test "rejects tampered authentication data without returning advanced state" do
    state = state()
    <<header::binary-size(5), body::binary>> = @record
    tampered_record = header <> flip_first_bit(body)

    assert {:error, :authentication_failed} = Record.decrypt(state, tampered_record)

    assert {:error, :authentication_failed} =
             Record.decrypt(state, flip_last_bit(@record))

    assert state.sequence == 0

    <<type, version::16, length::16, encrypted::binary>> = @record
    tampered_header = <<type, version::16, length - 1::16, encrypted::binary>>

    assert {:error, {:record_length_mismatch, 24, 25}} =
             Record.decrypt(state, tampered_header)
  end

  test "rejects authenticated inner plaintext with no content type" do
    state = state()
    header = <<23, 3, 3, 17::16>>
    assert {:ok, ciphertext, tag} = AEAD.encrypt(state, header, <<0>>)

    assert {:error, :missing_inner_content_type} =
             Record.decrypt(state, <<header::binary, ciphertext::binary, tag::binary>>)

    assert state.sequence == 0
  end

  test "authenticates a tag-only record before rejecting empty inner plaintext" do
    state = state()
    record = authenticate_raw(<<>>)

    assert {:error, :empty_inner_plaintext} = Record.decrypt(state, record)
    assert {:error, :authentication_failed} = Record.decrypt(state, flip_last_bit(record))
    assert state.sequence == 0
  end

  test "rejects authenticated oversized and empty handshake or alert inner plaintext" do
    maximum_content = :binary.copy(<<1>>, 16_384)

    assert {:error, {:inner_plaintext_length_exceeded, 16_386, 16_385}} =
             Record.decrypt(state(), authenticate_raw(maximum_content <> <<22, 0>>))

    for type <- [21, 22] do
      assert {:error, {:empty_content, decoded_type}} =
               Record.decrypt(state(), authenticate_raw(<<type>>))

      assert decoded_type in [:alert, :handshake]

      assert {:error, {:empty_content, ^decoded_type}} =
               Record.decrypt(state(), authenticate_raw(<<type, 0>>))
    end

    assert {:ok, :application_data, <<>>, %TrafficState{sequence: 1}} =
             Record.decrypt(state(), authenticate_raw(<<23>>))
  end

  test "rejects authenticated prohibited and unknown inner content types" do
    state = state()

    for type <- [20, 25] do
      assert {:error, {:unsupported_inner_content_type, ^type}} =
               Record.decrypt(state, authenticate_raw(<<1, type>>))
    end

    assert state.sequence == 0
  end

  test "validates the exact TLSCiphertext framing contract" do
    state = state()

    assert {:error, {:invalid_record, :not_binary}} = Record.decrypt(state, nil)
    assert {:error, {:malformed_record, :header}} = Record.decrypt(state, <<23, 3>>)

    assert {:error, {:unexpected_outer_content_type, 22}} =
             Record.decrypt(state, replace_header(@record, 22, 0x0303, 25))

    assert {:error, {:invalid_legacy_record_version, 0x0304}} =
             Record.decrypt(state, replace_header(@record, 23, 0x0304, 25))

    assert {:error, {:record_length_mismatch, 26, 25}} =
             Record.decrypt(state, replace_header(@record, 23, 0x0303, 26))

    assert {:error, {:ciphertext_length_too_short, 15, 16}} =
             Record.decrypt(state, <<23, 3, 3, 15::16, 0::120>>)

    assert {:error, :authentication_failed} =
             Record.decrypt(state, <<23, 3, 3, 16::16, 0::128>>)

    assert {:error, {:record_length_exceeded, 16_641, 16_640}} =
             Record.decrypt(state, <<23, 3, 3, 16_641::16, 0::size(16_641 * 8)>>)
  end

  test "rejects malformed encryption inputs and options" do
    state = state()

    assert {:error, :invalid_traffic_state} = Record.encrypt(nil, :handshake, <<>>)

    assert {:error, {:unsupported_inner_content_type, nil}} =
             Record.encrypt(state, nil, <<>>)

    assert {:error, {:invalid_content, :not_binary}} =
             Record.encrypt(state, :handshake, nil)

    assert {:error, {:invalid_options, :record}} =
             Record.encrypt(state, :handshake, <<>>, nil)

    assert {:error, {:invalid_options, :record}} =
             Record.encrypt(state, :handshake, <<>>, unknown: true)
  end

  test "rejects sequence exhaustion without wrapping" do
    exhausted = %{state() | sequence: 0xFFFFFFFFFFFFFFFF}

    assert {:error, :sequence_exhausted} = Record.encrypt(exhausted, :handshake, <<1>>)
    assert {:error, :sequence_exhausted} = Record.decrypt(exhausted, @record)
    assert exhausted.sequence == 0xFFFFFFFFFFFFFFFF
  end

  test "decrypts records after arbitrary TCP fragmentation through RecordFramer" do
    for split <- 0..byte_size(@record) do
      <<first::binary-size(^split), second::binary>> = @record
      {records, remainder} = feed_chunks([first, second])
      assert [record] = records
      assert RecordFramer.buffered_bytes(remainder) == <<>>

      assert {:ok, :handshake, "hello", %TrafficState{sequence: 1}} =
               Record.decrypt(state(), record)
    end
  end

  property "bounded malformed records return tagged results without raising" do
    check all(record <- binary(max_length: 256), max_runs: 100) do
      assert match?({:ok, _type, _content, _state}, Record.decrypt(state(), record)) or
               match?({:error, _reason}, Record.decrypt(state(), record))
    end
  end

  defp state do
    %TrafficState{
      secret: <<>>,
      key: @key,
      iv: @iv,
      cipher_suite: :tls_aes_128_gcm_sha256
    }
  end

  defp replace_header(<<_header::binary-size(5), body::binary>>, type, version, length) do
    <<type, version::16, length::16, body::binary>>
  end

  defp authenticate_raw(inner_plaintext) do
    length = byte_size(inner_plaintext) + 16
    header = <<23, 3, 3, length::16>>
    assert {:ok, ciphertext, tag} = AEAD.encrypt(state(), header, inner_plaintext)
    <<header::binary, ciphertext::binary, tag::binary>>
  end

  defp feed_chunks(chunks) do
    Enum.reduce(chunks, {[], RecordFramer.new()}, fn chunk, {records, framer} ->
      assert {:ok, complete, remainder} = RecordFramer.feed(framer, chunk)
      {records ++ complete, remainder}
    end)
  end

  defp flip_first_bit(<<first, rest::binary>>), do: <<Bitwise.bxor(first, 1), rest::binary>>

  defp flip_last_bit(binary) do
    prefix_size = byte_size(binary) - 1
    <<prefix::binary-size(^prefix_size), last>> = binary
    <<prefix::binary, Bitwise.bxor(last, 1)>>
  end
end
