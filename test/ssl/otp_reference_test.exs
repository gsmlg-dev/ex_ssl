defmodule SSL.OTPReferenceTest do
  use ExUnit.Case, async: false

  alias ExSSL.TestSupport.LocalTLSPeer

  @moduletag :otp_reference

  test "OTP ssl recv with a positive length preserves the surplus" do
    {:ok, peer} = LocalTLSPeer.start(fn socket -> :ok = :ssl.send(socket, "abcdef") end)
    {:ok, socket} = :ssl.connect(~c"127.0.0.1", peer.port, LocalTLSPeer.client_options(), 5_000)

    assert {:ok, "abc"} = :ssl.recv(socket, 3, 1_000)
    assert {:ok, "def"} = :ssl.recv(socket, 3, 1_000)
    assert :ok = :ssl.close(socket)
    assert :ok = LocalTLSPeer.stop(peer)
  end

  test "OTP ssl recv zero returns decrypted application bytes" do
    {:ok, peer} = LocalTLSPeer.start(fn socket -> :ok = :ssl.send(socket, "available") end)
    {:ok, socket} = :ssl.connect(~c"127.0.0.1", peer.port, LocalTLSPeer.client_options(), 5_000)

    assert {:ok, "available"} = :ssl.recv(socket, 0, 1_000)
    assert :ok = :ssl.close(socket)
    assert :ok = LocalTLSPeer.stop(peer)
  end

  test "OTP ssl recv exact-length timeout does not return partial plaintext" do
    {:ok, peer} =
      LocalTLSPeer.start(fn socket ->
        :ok = :ssl.send(socket, "abc")
        Process.sleep(150)
        :ok = :ssl.send(socket, "def")
      end)

    {:ok, socket} = :ssl.connect(~c"127.0.0.1", peer.port, LocalTLSPeer.client_options(), 5_000)

    assert {:error, :timeout} = :ssl.recv(socket, 6, 25)
    assert {:ok, "abcdef"} = :ssl.recv(socket, 6, 1_000)
    assert :ok = :ssl.close(socket)
    assert :ok = LocalTLSPeer.stop(peer)
  end

  test "OTP ssl serializes concurrent passive receives" do
    {:ok, peer} =
      LocalTLSPeer.start(fn socket ->
        Process.sleep(50)
        :ok = :ssl.send(socket, "one")
        :ok = :ssl.send(socket, "two")
      end)

    {:ok, socket} = :ssl.connect(~c"127.0.0.1", peer.port, LocalTLSPeer.client_options(), 5_000)
    parent = self()

    pids =
      for label <- [:first, :second] do
        spawn(fn -> send(parent, {label, :ssl.recv(socket, 3, 1_000)}) end)
      end

    assert_receive {label, {:ok, "one"}}, 1_500
    other_label = if label == :first, do: :second, else: :first
    refute_receive {^other_label, _result}, 100

    assert :ok = :ssl.close(socket)
    assert_receive {^other_label, {:error, :closed}}, 1_500
    assert Enum.all?(pids, &(!Process.alive?(&1)))
    assert :ok = LocalTLSPeer.stop(peer)
  end

  test "OTP ssl reports closed sockets consistently to send, recv, and close" do
    {:ok, peer} =
      LocalTLSPeer.start(fn socket ->
        assert {:error, :closed} = :ssl.recv(socket, 0, 5_000)
        :ok
      end)

    {:ok, socket} = :ssl.connect(~c"127.0.0.1", peer.port, LocalTLSPeer.client_options(), 5_000)

    assert :ok = :ssl.close(socket)
    assert {:error, :closed} = :ssl.send(socket, "after-close")
    assert {:error, :closed} = :ssl.recv(socket, 0, 0)
    assert :ok = :ssl.close(socket)
    assert :ok = LocalTLSPeer.stop(peer)
  end
end
