defmodule SSL.Connection do
  @moduledoc false
  @behaviour :gen_statem
  alias SSL.{Options, Socket}
  alias SSL.ClientHello.Materializer
  alias SSL.Protocol.{HandshakeMachine, RecordFramer}

  @max_plaintext 1_048_576
  @max_write 1_048_576
  @rearm_reserve 65_536
  @alert_codes %{
    unexpected_message: 10,
    bad_record_mac: 20,
    record_overflow: 22,
    handshake_failure: 40,
    bad_certificate: 42,
    certificate_expired: 45,
    certificate_unknown: 46,
    illegal_parameter: 47,
    unknown_ca: 48,
    decode_error: 50,
    decrypt_error: 51,
    protocol_version: 70,
    internal_error: 80,
    missing_extension: 109,
    unsupported_extension: 110,
    certificate_required: 116
  }

  defmodule State do
    @moduledoc false
    @derive {Inspect, only: [:socket, :armed, :size, :closed]}
    defstruct [
      :socket,
      :tcp,
      :owner,
      :owner_monitor,
      :options,
      :deadline,
      :machine,
      :connect_from,
      :recv,
      :write,
      :handshake_timer,
      records: nil,
      buffer: :queue.new(),
      size: 0,
      armed: false,
      closed: false
    ]
  end

  @spec max_write_size() :: pos_integer()
  def max_write_size, do: @max_write

  def child_spec(args),
    do: %{id: __MODULE__, start: {__MODULE__, :start_link, [args]}, restart: :temporary}

  def start_link(args), do: :gen_statem.start_link(__MODULE__, args, [])

  @impl true
  def callback_mode, do: :handle_event_function

  @impl true
  def init({owner, ref, status, options, deadline}) do
    Process.flag(:sensitive, true)

    state = %State{
      socket: %Socket{pid: self(), ref: ref, status: status},
      owner: owner,
      owner_monitor: Process.monitor(owner),
      options: options,
      deadline: deadline,
      records: RecordFramer.new(),
      handshake_timer: timer(deadline, :handshake_timeout)
    }

    {:ok, :handoff, state}
  end

  @impl true
  def handle_event({:call, from}, {ref, _request}, _phase, %{socket: %{ref: actual}})
      when ref != actual,
      do: {:keep_state_and_data, [{:reply, from, {:error, :badarg}}]}

  def handle_event({:call, from}, {_ref, {:attach, tcp}}, :handoff, state) do
    state = %{state | tcp: tcp, connect_from: from}

    if Options.remaining(state.deadline) == 0 do
      fail(state, :timeout)
    else
      with :ok <-
             :inet.setopts(tcp, [
               :binary,
               packet: :raw,
               active: false,
               send_timeout: 5_000,
               send_timeout_close: true,
               buffer: 16_640
             ]),
           {:ok, materialized} <-
             Materializer.materialize(
               state.options.profile,
               Options.capabilities(),
               state.options.context
             ),
           {:ok, machine, outbound} <-
             HandshakeMachine.init(
               materialized,
               state.options.trust_source,
               state.options.identity,
               customize_hostname_check: state.options.hostname_check
             ),
           :ok <- :gen_tcp.send(tcp, outbound) do
        continue(:handshaking, %{state | machine: machine, options: nil})
      else
        {:error, reason} -> fail(state, public_error(reason))
      end
    end
  end

  def handle_event({:call, from}, {_ref, :close}, _phase, state) do
    Socket.mark_terminal(state.socket, true)
    notify_pending(state, {:error, :closed})
    state = close_notify(state)
    {:stop_and_reply, :normal, [{:reply, from, :ok}], state}
  end

  def handle_event({:call, from}, {_ref, {:recv, length, deadline}}, :connected, state) do
    cond do
      length > @max_plaintext ->
        reply(from, {:error, :emsgsize})

      state.recv != nil ->
        reply(from, {:error, :einval})

      true ->
        token = make_ref()

        receiver = %{
          from: from,
          length: length,
          deadline: deadline,
          token: token,
          monitor: Process.monitor(elem(from, 0)),
          timer: timer(deadline, {:recv_timeout, token})
        }

        continue(:connected, deliver(%{state | recv: receiver}, true))
    end
  end

  def handle_event({:call, from}, {_ref, :reserve_write}, :connected, state) do
    cond do
      state.closed ->
        reply(from, {:error, :closed})

      state.write != nil ->
        reply(from, {:error, :busy})

      true ->
        token = make_ref()

        write = %{
          token: token,
          owner: elem(from, 0),
          monitor: Process.monitor(elem(from, 0)),
          from: nil,
          data: nil
        }

        {:keep_state, %{state | write: write}, [{:reply, from, {:ok, token}}]}
    end
  end

  def handle_event(
        {:call, from},
        {_ref, {:send, token, iodata}},
        :connected,
        %{write: %{token: token, owner: owner, from: nil} = write} = state
      )
      when elem(from, 0) == owner do
    case write_bytes(iodata) do
      {:ok, bytes} ->
        send(self(), :write_next)
        {:keep_state, %{state | write: %{write | from: from, data: bytes}}}

      {:error, reason} ->
        Process.demonitor(write.monitor, [:flush])
        {:keep_state, %{state | write: nil}, [{:reply, from, {:error, reason}}]}
    end
  end

  def handle_event({:call, from}, {_ref, _}, _phase, _state), do: reply(from, {:error, :closed})

  def handle_event(:info, {:tcp, tcp, bytes}, phase, %{tcp: tcp} = state) do
    state = %{state | armed: false}

    with {:ok, records, framer} <- RecordFramer.feed(state.records, bytes),
         {:ok, state} <- process_records(records, %{state | records: framer}) do
      phase = if state.connect_from == nil, do: :connected, else: phase
      continue(phase, deliver(state))
    else
      {:error, reason, failed_state} -> fail(failed_state, public_error(reason))
      {:error, reason} -> fail(state, public_error(reason))
    end
  end

  def handle_event(:info, {:tcp_closed, tcp}, _phase, %{tcp: tcp} = state) do
    fail(state, :econnreset)
  end

  def handle_event(:info, {:tcp_error, tcp, reason}, _phase, %{tcp: tcp} = state),
    do: fail(state, reason)

  def handle_event(:info, :handshake_timeout, phase, state) when phase != :connected,
    do: fail(state, :timeout)

  def handle_event(:info, {:recv_timeout, token}, :connected, %{recv: %{token: token}} = state) do
    state = finish_recv(state, {:error, :timeout})
    continue(:connected, state)
  end

  def handle_event(:info, :write_next, :connected, %{write: %{from: from, data: <<>>}} = state)
      when from != nil do
    :gen_statem.reply(from, :ok)
    Process.demonitor(state.write.monitor, [:flush])
    {:keep_state, %{state | write: nil}}
  end

  def handle_event(:info, :write_next, :connected, %{write: %{data: bytes} = write} = state)
      when is_binary(bytes) do
    size = min(byte_size(bytes), 16_384)
    <<chunk::binary-size(^size), rest::binary>> = bytes

    with true <- Process.alive?(write.owner),
         {:ok, record, machine} <-
           HandshakeMachine.encrypt(state.machine, :application_data, chunk),
         state = %{state | machine: machine},
         :ok <- :gen_tcp.send(state.tcp, record) do
      send(self(), :write_next)
      {:keep_state, %{state | write: %{write | data: rest}}}
    else
      false -> fail(state, :closed)
      {:error, reason} -> fail(state, public_error(reason))
    end
  end

  def handle_event(
        :info,
        {:DOWN, monitor, :process, _pid, _reason},
        _phase,
        %{owner_monitor: monitor} = state
      ) do
    Socket.mark_terminal(state.socket, true)
    fail(close_notify(state), :closed)
  end

  def handle_event(
        :info,
        {:DOWN, monitor, :process, _pid, _reason},
        phase,
        %{recv: %{monitor: monitor}} = state
      ) do
    cancel_timer(state.recv.timer)
    continue(phase, %{state | recv: nil})
  end

  def handle_event(
        :info,
        {:DOWN, monitor, :process, _pid, _reason},
        _phase,
        %{write: %{monitor: monitor, from: from}} = state
      ) do
    if from == nil, do: {:keep_state, %{state | write: nil}}, else: fail(state, :closed)
  end

  def handle_event(:info, _message, _phase, _state), do: :keep_state_and_data

  @impl true
  def terminate(_reason, _phase, state) do
    Socket.mark_terminal(state.socket, false)
    if state.tcp, do: :gen_tcp.close(state.tcp)
    cancel_timer(state.handshake_timer)

    if state.recv do
      cancel_timer(state.recv.timer)
      Process.demonitor(state.recv.monitor, [:flush])
    end

    if state.write, do: Process.demonitor(state.write.monitor, [:flush])
    Process.demonitor(state.owner_monitor, [:flush])
    :ok
  end

  @impl true
  def format_status(status) do
    Map.merge(status, %{data: :redacted, reason: :redacted, log: [], queue: [], postponed: []})
  end

  defp process_records([], state), do: {:ok, state}

  defp process_records([record | rest], state) do
    case HandshakeMachine.feed(state.machine, record) do
      {:ok, machine, outbound, events} ->
        state = %{state | machine: machine}

        with :ok <- send_records(state.tcp, outbound),
             {:ok, state} <- apply_events(events, state) do
          if state.closed and rest != [],
            do: {:error, :closed, state},
            else: process_records(rest, state)
        else
          {:error, reason} -> {:error, reason, state}
        end

      {:error, reason} ->
        {:error, reason, state}
    end
  end

  defp apply_events([], state), do: {:ok, state}

  defp apply_events([:connected | rest], state) do
    if Options.remaining(state.deadline) == 0 do
      {:error, :timeout}
    else
      :gen_statem.reply(state.connect_from, {:ok, state.socket})
      cancel_timer(state.handshake_timer)
      apply_events(rest, %{state | connect_from: nil, handshake_timer: nil})
    end
  end

  defp apply_events([{:application_data, bytes} | rest], state) do
    if state.size + byte_size(bytes) <= @max_plaintext do
      state =
        if bytes == <<>>,
          do: state,
          else: %{
            state
            | buffer: :queue.in(bytes, state.buffer),
              size: state.size + byte_size(bytes)
          }

      apply_events(rest, deliver(state))
    else
      {:error, :enobufs}
    end
  end

  defp apply_events([:closed | rest], state) do
    Socket.mark_terminal(state.socket, true)
    state = close_notify(state)
    if state.tcp, do: :gen_tcp.close(state.tcp)
    apply_events(rest, %{state | closed: true, tcp: nil, machine: nil, armed: false})
  end

  defp deliver(state, immediate \\ false)
  defp deliver(%{recv: nil} = state, _immediate), do: state

  defp deliver(%{recv: receiver} = state, immediate) do
    cond do
      not Process.alive?(elem(receiver.from, 0)) ->
        cancel_timer(receiver.timer)
        Process.demonitor(receiver.monitor, [:flush])
        %{state | recv: nil}

      not immediate and Options.remaining(receiver.deadline) == 0 ->
        finish_recv(state, {:error, :timeout})

      receiver.length == 0 and state.size > 0 ->
        deliver_bytes(state, state.size)

      receiver.length > 0 and state.size >= receiver.length ->
        deliver_bytes(state, receiver.length)

      state.closed ->
        finish_recv(state, {:error, :closed})

      Options.remaining(receiver.deadline) == 0 ->
        finish_recv(state, {:error, :timeout})

      true ->
        state
    end
  end

  defp deliver_bytes(state, length) do
    {bytes, buffer} = take(state.buffer, length, [])
    finish_recv(%{state | buffer: buffer, size: state.size - length}, {:ok, bytes})
  end

  defp take(buffer, 0, acc), do: {IO.iodata_to_binary(Enum.reverse(acc)), buffer}

  defp take(buffer, length, acc) do
    {{:value, chunk}, buffer} = :queue.out(buffer)

    if byte_size(chunk) <= length do
      take(buffer, length - byte_size(chunk), [chunk | acc])
    else
      <<head::binary-size(^length), tail::binary>> = chunk
      {IO.iodata_to_binary(Enum.reverse([head | acc])), :queue.in_r(tail, buffer)}
    end
  end

  defp finish_recv(state, result) do
    :gen_statem.reply(state.recv.from, result)
    cancel_timer(state.recv.timer)
    Process.demonitor(state.recv.monitor, [:flush])
    %{state | recv: nil}
  end

  defp continue(_phase, %{closed: true, size: 0} = state) do
    notify_pending(state, {:error, :closed})
    {:stop, :normal, state}
  end

  defp continue(phase, state) do
    can_read = state.size < @max_plaintext - @rearm_reserve or state.recv != nil

    if state.tcp && not state.armed && not state.closed && can_read do
      case :inet.setopts(state.tcp, active: :once) do
        :ok -> {:next_state, phase, %{state | armed: true}}
        {:error, reason} -> fail(state, reason)
      end
    else
      {:next_state, phase, state}
    end
  end

  defp fail(state, {:peer_alert, _level, description}) do
    category =
      Enum.find_value(@alert_codes, :handshake_failure, fn {name, code} ->
        if code == description, do: name
      end)

    notify_pending(state, {:error, {:tls_alert, {category, ~c"Peer terminated TLS"}}})
    {:stop, :normal, state}
  end

  defp fail(state, reason) do
    notify_pending(state, {:error, reason})
    {:stop, :normal, fatal_alert(state, reason)}
  end

  defp fatal_alert(%{machine: nil} = state, _reason), do: state

  defp fatal_alert(state, {:tls_alert, {alert, _description}}) do
    code = @alert_codes[alert] || 80

    case HandshakeMachine.encrypt(state.machine, :alert, <<2, code>>) do
      {:ok, record, machine} ->
        if state.tcp, do: :gen_tcp.send(state.tcp, record)
        %{state | machine: machine}

      _ ->
        state
    end
  end

  defp fatal_alert(state, _reason), do: state

  defp notify_pending(state, result) do
    if state.connect_from, do: :gen_statem.reply(state.connect_from, result)
    if state.recv, do: :gen_statem.reply(state.recv.from, result)
    if state.write && state.write.from, do: :gen_statem.reply(state.write.from, result)
  end

  defp close_notify(%{machine: nil} = state), do: state

  defp close_notify(state) do
    case HandshakeMachine.encrypt(state.machine, :alert, <<1, 0>>) do
      {:ok, record, machine} ->
        if state.tcp, do: :gen_tcp.send(state.tcp, record)
        %{state | machine: machine}

      _ ->
        state
    end
  end

  defp public_error({:fatal_alert, alert, _}), do: {:tls_alert, {alert, ~c"TLS protocol error"}}
  defp public_error({:peer_alert, _, _} = alert), do: alert

  defp public_error({:record_length_exceeded, _, _}),
    do: {:tls_alert, {:record_overflow, ~c"Record limit exceeded"}}

  defp public_error(reason) when is_atom(reason), do: reason
  defp public_error(_), do: {:tls_alert, {:internal_error, ~c"TLS connection failed"}}
  defp reply(from, result), do: {:keep_state_and_data, [{:reply, from, result}]}
  defp timer(:infinity, _message), do: nil

  defp timer(deadline, message),
    do: Process.send_after(self(), message, Options.remaining(deadline))

  defp cancel_timer(nil), do: :ok
  defp cancel_timer(timer), do: Process.cancel_timer(timer, async: false, info: false)
  defp send_records(_tcp, []), do: :ok
  defp send_records(tcp, records), do: :gen_tcp.send(tcp, records)

  defp write_bytes(iodata) do
    if :erlang.iolist_size(iodata) <= @max_write,
      do: {:ok, IO.iodata_to_binary(iodata)},
      else: {:error, :emsgsize}
  rescue
    ArgumentError -> {:error, :badarg}
  end
end
