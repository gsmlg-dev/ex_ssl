defmodule SSL.Protocol.InnerPlaintextTest do
  use ExUnit.Case, async: true
  use ExUnitProperties

  alias SSL.Protocol.InnerPlaintext

  test "encodes content, inner type, and zero padding exactly" do
    assert {:ok, <<"hello", 22, 0, 0, 0>>} =
             InnerPlaintext.encode("hello", :handshake, 3)
  end

  test "decodes the final nonzero type and preserves content ending in zeros" do
    assert {:ok, :application_data, <<1, 0, 0>>, 4} =
             InnerPlaintext.decode(<<1, 0, 0, 23, 0, 0, 0, 0>>)
  end

  test "supports handshake, alert, and application data types" do
    for type <- [:handshake, :alert, :application_data] do
      assert {:ok, encoded} = InnerPlaintext.encode("content", type, 2)
      assert {:ok, ^type, "content", 2} = InnerPlaintext.decode(encoded)
    end
  end

  test "rejects empty, all-zero, and unsupported inner plaintext" do
    assert {:error, :empty_inner_plaintext} = InnerPlaintext.decode(<<>>)
    assert {:error, :missing_inner_content_type} = InnerPlaintext.decode(<<0, 0, 0>>)

    assert {:error, {:unsupported_inner_content_type, 24}} =
             InnerPlaintext.decode(<<1, 24, 0>>)

    assert {:error, {:unsupported_inner_content_type, :change_cipher_spec}} =
             InnerPlaintext.encode(<<>>, :change_cipher_spec, 0)
  end

  test "enforces content, padding, and total inner plaintext bounds" do
    assert {:error, {:invalid_content, :not_binary}} =
             InnerPlaintext.encode(nil, :handshake, 0)

    assert {:error, {:content_length_exceeded, 16_385, 16_384}} =
             InnerPlaintext.encode(:binary.copy(<<0>>, 16_385), :handshake, 0)

    assert {:error, {:invalid_padding_length, -1}} =
             InnerPlaintext.encode(<<>>, :handshake, -1)

    assert {:error, {:padding_length_exceeded, 16_624, 16_623}} =
             InnerPlaintext.encode(<<>>, :handshake, 16_624)

    assert {:ok, maximum} = InnerPlaintext.encode(<<>>, :handshake, 16_623)
    assert byte_size(maximum) == 16_624

    maximum_content = :binary.copy(<<1>>, 16_384)

    assert {:error, {:padding_length_exceeded, 240, 239}} =
             InnerPlaintext.encode(maximum_content, :handshake, 240)

    oversized_content = <<0::size(16_385 * 8), 22>>

    assert {:error, {:content_length_exceeded, 16_385, 16_384}} =
             InnerPlaintext.decode(oversized_content)

    assert {:error, {:inner_plaintext_length_exceeded, 16_625, 16_624}} =
             InnerPlaintext.decode(:binary.copy(<<0>>, 16_625))

    assert {:error, {:invalid_inner_plaintext, :not_binary}} = InnerPlaintext.decode(nil)
  end

  property "bounded content and padding round trip" do
    check all(
            content <- binary(max_length: 128),
            type <- member_of([:handshake, :alert, :application_data]),
            padding_length <- integer(0..64),
            max_runs: 100
          ) do
      assert {:ok, encoded} = InnerPlaintext.encode(content, type, padding_length)
      assert {:ok, ^type, ^content, ^padding_length} = InnerPlaintext.decode(encoded)
    end
  end
end
