defmodule SSL.Crypto.TrafficStateTest do
  use ExUnit.Case, async: true

  alias SSL.Crypto.TrafficState

  test "nonce XORs the static IV with the left-padded uint64 sequence number" do
    state = %TrafficState{
      secret: <<1>>,
      key: <<2>>,
      iv: Base.decode16!("AABBCCDDEEFF001122334455"),
      sequence: 0x0102030405060708,
      cipher_suite: :tls_aes_128_gcm_sha256
    }

    expected_nonce = Base.decode16!("AABBCCDDEFFD03152735435D")

    assert state.generation == 0
    assert {:ok, ^expected_nonce} = TrafficState.nonce(state)
  end

  test "nonce rejects IVs shorter than the uint64 sequence number" do
    state = %TrafficState{
      secret: <<1>>,
      key: <<2>>,
      iv: <<0::56>>,
      cipher_suite: :tls_aes_128_gcm_sha256
    }

    assert {:error, {:invalid_iv, :too_short}} = TrafficState.nonce(state)
  end

  test "nonce rejects IV lengths unsupported by the declared TLS 1.3 suites" do
    for iv <- [<<0::64>>, <<0::104>>] do
      state = %TrafficState{
        secret: <<1>>,
        key: <<2>>,
        iv: iv,
        cipher_suite: :tls_aes_128_gcm_sha256
      }

      assert {:error, {:invalid_iv, :wrong_length}} = TrafficState.nonce(state)
    end
  end

  test "nonce accepts the final uint64 sequence and rejects underflow or overflow" do
    state = %TrafficState{
      secret: <<1>>,
      key: <<2>>,
      iv: <<0::96>>,
      cipher_suite: :tls_aes_128_gcm_sha256
    }

    assert {:ok, <<0::32, 0xFFFFFFFFFFFFFFFF::64>>} =
             TrafficState.nonce(%{state | sequence: 0xFFFFFFFFFFFFFFFF})

    assert {:error, {:invalid_sequence, :out_of_range}} =
             TrafficState.nonce(%{state | sequence: -1})

    assert {:error, {:invalid_sequence, :out_of_range}} =
             TrafficState.nonce(%{state | sequence: 0x10000000000000000})
  end

  test "inspection redacts traffic secrets and derived key material" do
    state = %TrafficState{
      secret: "unique traffic secret",
      key: "unique traffic key",
      iv: "unique traffic iv",
      cipher_suite: :tls_aes_128_gcm_sha256
    }

    inspected = inspect(state)

    refute inspected =~ "unique traffic secret"
    refute inspected =~ "unique traffic key"
    refute inspected =~ "unique traffic iv"
    refute inspected =~ "secret:"
    refute inspected =~ "key:"
    refute inspected =~ "iv:"
  end
end
