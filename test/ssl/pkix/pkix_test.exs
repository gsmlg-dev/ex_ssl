defmodule SSL.PKIXTest do
  use ExUnit.Case, async: true
  use ExUnitProperties

  alias SSL.PKIX
  alias SSL.PKIX.Certificate
  alias SSL.PKIX.VerifiedPeer

  @fixture_dir Path.expand("../../fixtures/pkix", __DIR__)
  @leaf_pem File.read!(Path.join(@fixture_dir, "leaf.pem"))
  @root_pem File.read!(Path.join(@fixture_dir, "root.pem"))
  @wrong_root_pem File.read!(Path.join(@fixture_dir, "wrong_root.pem"))
  @leaf_der @leaf_pem |> :public_key.pem_decode() |> hd() |> elem(1)
  @root_der @root_pem |> :public_key.pem_decode() |> hd() |> elem(1)
  @wrong_root_der @wrong_root_pem |> :public_key.pem_decode() |> hd() |> elem(1)

  test "decodes an ordered leaf-first DER chain without discarding exact bytes" do
    assert {:ok, [%Certificate{der: @leaf_der}, %Certificate{der: @root_der}]} =
             PKIX.decode_chain([@leaf_der, @root_der])
  end

  test "normalizes DER lists and PEM bundles into trust anchors" do
    assert {:ok, [%Certificate{der: @root_der}]} = PKIX.normalize_trust([@root_der])
    assert {:ok, [%Certificate{der: @root_der}]} = PKIX.normalize_trust(@root_pem)
  end

  test "validates a path and DNS service identity and exposes the verified leaf" do
    assert {:ok,
            %VerifiedPeer{
              leaf_der: @leaf_der,
              leaf: leaf,
              public_key: {{:ECPoint, <<4, _::binary-size(64)>>}, {:namedCurve, _}}
            }} = PKIX.verify([@leaf_der], @root_pem, {:dns_id, "example.test"})

    assert leaf == :public_key.pkix_decode_cert(@leaf_der, :otp)
  end

  test "validates an IP subject alternative name" do
    assert {:ok, %VerifiedPeer{leaf_der: @leaf_der}} =
             PKIX.verify([@leaf_der], [@root_der], {:ip, {127, 0, 0, 1}})
  end

  test "accepts a peer chain that includes the supplied trust anchor" do
    assert {:ok, %VerifiedPeer{leaf_der: @leaf_der}} =
             PKIX.verify(
               [@leaf_der, @root_der],
               [@root_der],
               {:dns_id, "example.test"}
             )
  end

  test "rejects hostname mismatches and paths outside the supplied trust" do
    assert {:error, :hostname_mismatch} =
             PKIX.verify([@leaf_der], [@root_der], {:dns_id, "wrong.example.test"})

    assert {:error, {:path_validation_failed, _reason}} =
             PKIX.verify([@leaf_der], [@wrong_root_der], {:dns_id, "example.test"})
  end

  test "rejects malformed and tampered certificates" do
    tampered_leaf = flip_last_bit(@leaf_der)

    assert {:error, {:invalid_certificate, 0}} = PKIX.decode_chain([<<1, 2, 3>>])

    assert {:error, {:path_validation_failed, _reason}} =
             PKIX.verify([tampered_leaf], [@root_der], {:dns_id, "example.test"})

    assert {:error, :malformed_pem} = PKIX.normalize_trust("not a PEM bundle")
    assert {:error, {:invalid_certificate, 0}} = PKIX.normalize_trust([<<0>>])
  end

  test "rejects empty inputs and malformed arbitrary terms" do
    assert {:error, :empty_certificate_chain} = PKIX.decode_chain([])
    assert {:error, :empty_trust_anchors} = PKIX.normalize_trust([])
    assert {:error, :empty_trust_anchors} = PKIX.normalize_trust(<<>>)
    assert {:error, {:invalid_input, :certificate_chain}} = PKIX.decode_chain(nil)
    assert {:error, {:invalid_input, :trust_source}} = PKIX.normalize_trust(nil)

    assert {:error, {:invalid_identity, nil}} = PKIX.verify([@leaf_der], [@root_der], nil)

    assert {:error, {:invalid_input, :options}} = PKIX.decode_chain([@leaf_der], nil)
  end

  test "enforces certificate count, individual DER, total DER, and PEM bounds" do
    assert {:error, {:certificate_count_limit_exceeded, 2, 1}} =
             PKIX.decode_chain([@leaf_der, @root_der], max_certificates: 1)

    assert {:error, {:certificate_der_limit_exceeded, 0, actual, 10}} =
             PKIX.decode_chain([@leaf_der], max_der_bytes: 10)

    assert actual == byte_size(@leaf_der)

    assert {:error, {:certificate_total_der_limit_exceeded, total, 1_000}} =
             PKIX.decode_chain([@leaf_der, @root_der], max_total_der_bytes: 1_000)

    assert total == byte_size(@leaf_der) + byte_size(@root_der)

    assert {:error, {:pem_limit_exceeded, pem_size, 10}} =
             PKIX.normalize_trust(@root_pem, max_pem_bytes: 10)

    assert pem_size == byte_size(@root_pem)
  end

  property "bounded malformed PKIX inputs always return tagged results" do
    malformed_entry = one_of([constant(nil), constant(false), integer(), binary(max_length: 32)])

    malformed_input =
      one_of([
        malformed_entry,
        list_of(malformed_entry, max_length: 8)
      ])

    check all(input <- malformed_input, max_runs: 100) do
      for result <- [
            PKIX.decode_chain(input),
            PKIX.normalize_trust(input),
            PKIX.verify(input, [@root_der], {:dns_id, "example.test"})
          ] do
        assert match?({:ok, _value}, result) or match?({:error, _reason}, result)
      end
    end
  end

  defp flip_last_bit(der) do
    prefix_size = byte_size(der) - 1
    <<prefix::binary-size(^prefix_size), last>> = der
    <<prefix::binary, Bitwise.bxor(last, 1)>>
  end
end
