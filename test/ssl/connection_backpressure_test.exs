defmodule SSL.ConnectionBackpressureTest do
  use ExUnit.Case, async: false

  alias ExSSL.TestSupport.LocalTLSPeer, as: Peer

  @moduletag :integration
  @payload_size 16 * 1_048_576

  test "real TCP backpressure recovers without replay across a requested KeyUpdate" do
    parent = self()
    peer_ready_ref = make_ref()
    payload = :binary.copy("k", @payload_size)

    {:ok, peer} =
      Peer.start(fn socket ->
        send(parent, {:backpressure_peer_ready, peer_ready_ref})

        receive do
          :request_update -> :ok
        end

        send(parent, :backpressure_key_update_started)
        update_result = :ssl.update_keys(socket, :read_write)
        send(parent, {:backpressure_key_update, update_result})
        result = :ssl.recv(socket, byte_size(payload), 30_000)
        send(parent, {:backpressure_payload, result})
        assert :ok = :ssl.send(socket, "recovered")
        assert {:error, :closed} = :ssl.recv(socket, 0, 5_000)
        :ok
      end)

    {:ok, proxy} = Peer.start_backpressure_proxy(peer.port, self())
    proxy_ref = proxy.ref

    try do
      socket = connect(proxy.port, send_timeout: :infinity)
      assert_receive {:backpressure_proxy, ^proxy_ref, :ready}, 1_000
      assert_receive {:backpressure_peer_ready, ^peer_ready_ref}, 5_000
      assert :ok = Peer.pause_client_to_server(proxy, self())
      assert_receive {:backpressure_proxy, ^proxy_ref, :paused}, 1_000

      sender = Task.async(fn -> SSL.send(socket, payload) end)
      assert_receive {:backpressure_proxy, ^proxy_ref, :held, held}, 5_000
      assert held > 0
      assert_writer_is_socket_blocked(socket, sender)

      send(peer.task.pid, :request_update)
      assert_receive :backpressure_key_update_started, 5_000
      wait_for_pending_input(socket.pid)
      assert :ok = Peer.resume_client_to_server(proxy, self())
      assert_receive {:backpressure_proxy, ^proxy_ref, :resumed}, 1_000

      assert :ok = Task.await(sender, 30_000)
      assert_receive {:backpressure_key_update, :ok}, 5_000
      assert_receive {:backpressure_payload, {:ok, ^payload}}, 30_000
      assert {:ok, "recovered"} = SSL.recv(socket, 9, 5_000)
      assert :ok = SSL.close(socket)
      assert :ok = Peer.stop(peer)
    after
      if Process.alive?(proxy.task.pid), do: Peer.stop_backpressure_proxy(proxy)
      stop_peer_on_failure(peer)
    end
  end

  test "close cancels an infinite-timeout write blocked by real TCP backpressure" do
    parent = self()
    peer_ready_ref = make_ref()
    payload = :binary.copy("c", @payload_size)

    {:ok, peer} =
      Peer.start(fn socket ->
        send(parent, {:backpressure_peer_ready, peer_ready_ref})

        case :ssl.recv(socket, byte_size(payload), 30_000) do
          {:ok, _bytes} -> :unexpected_complete_payload
          {:error, _reason} -> :closed
        end
      end)

    {:ok, proxy} = Peer.start_backpressure_proxy(peer.port, self())
    proxy_ref = proxy.ref

    try do
      socket = connect(proxy.port, send_timeout: :infinity)
      assert_receive {:backpressure_proxy, ^proxy_ref, :ready}, 1_000
      assert_receive {:backpressure_peer_ready, ^peer_ready_ref}, 5_000
      assert :ok = Peer.pause_client_to_server(proxy, self())
      assert_receive {:backpressure_proxy, ^proxy_ref, :paused}, 1_000

      {:connected, state} = :sys.get_state(socket.pid)
      connection_monitor = Process.monitor(socket.pid)
      writer_monitor = Process.monitor(state.writer)
      sender = Task.async(fn -> SSL.send(socket, payload) end)
      assert_receive {:backpressure_proxy, ^proxy_ref, :held, _held}, 5_000
      assert_writer_is_socket_blocked(socket, sender)

      started = System.monotonic_time(:millisecond)
      assert :ok = SSL.close(socket)
      assert System.monotonic_time(:millisecond) - started < 1_000
      assert {:error, :closed} = Task.await(sender, 1_000)
      assert_receive {:DOWN, ^connection_monitor, :process, _, :normal}, 1_000
      assert_receive {:DOWN, ^writer_monitor, :process, _, :killed}, 1_000
      _ = Peer.stop_backpressure_proxy(proxy)
      _ = :ssl.close(peer.listener)
      _ = Task.shutdown(peer.task, :brutal_kill)
      refute Process.alive?(peer.task.pid)
    after
      if Process.alive?(proxy.task.pid), do: Peer.stop_backpressure_proxy(proxy)
      stop_peer_on_failure(peer)
    end
  end

  defp assert_writer_is_socket_blocked(socket, sender) do
    wait_for_output(socket.pid)
    deadline = System.monotonic_time(:millisecond) + 5_000
    wait_for_stable_output(socket, sender, deadline)
  end

  defp wait_for_stable_output(socket, sender, deadline) do
    {:connected, first} = :sys.get_state(socket.pid)
    token = first.output.token
    writer = first.writer
    Process.send_after(self(), {:backpressure_watchdog, token}, 50)

    assert_receive {:backpressure_watchdog, ^token}, 1_000
    assert Task.yield(sender, 0) == nil
    {:connected, second} = :sys.get_state(socket.pid)

    if second.output.token == token do
      assert Process.alive?(writer)

      assert Process.info(writer, :current_function) !=
               {:current_function, {SSL.ConnectionWriter, :loop, 2}}
    else
      assert System.monotonic_time(:millisecond) < deadline
      wait_for_stable_output(socket, sender, deadline)
    end
  end

  defp wait_for_output(pid, attempts \\ 5_000)
  defp wait_for_output(_pid, 0), do: flunk("connection writer never became pending")

  defp wait_for_output(pid, attempts) do
    case :sys.get_state(pid) do
      {:connected, %{output: %{kind: :application}}} ->
        :ok

      _ ->
        Process.sleep(1)
        wait_for_output(pid, attempts - 1)
    end
  end

  defp wait_for_pending_input(pid, attempts \\ 1_000)
  defp wait_for_pending_input(_pid, 0), do: flunk("KeyUpdate was not queued behind output")

  defp wait_for_pending_input(pid, attempts) do
    case :sys.get_state(pid) do
      {:connected, %{input_size: size}} when size > 0 ->
        :ok

      _ ->
        Process.sleep(1)
        wait_for_pending_input(pid, attempts - 1)
    end
  end

  defp connect(port, extra_options) do
    options = [:binary | Keyword.merge(tl(Peer.client_options()), extra_options)]
    assert {:ok, socket} = SSL.connect(~c"127.0.0.1", port, options, 5_000)
    socket
  end

  defp stop_peer_on_failure(peer) do
    if Process.alive?(peer.task.pid) do
      _ = :ssl.close(peer.listener)
      _ = Task.shutdown(peer.task, 1_000)
    end
  end
end
