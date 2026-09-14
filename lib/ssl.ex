defmodule SSL do
  @moduledoc """
  OTP `:ssl`-compatible client facade for the implemented `ex_ssl` feature subset.

  This experimental client supports TLS 1.3, binary passive raw sockets and
  mandatory peer verification. These restricted defaults differ from OTP.
  Unsupported options return explicit `{:error, {:options, reason}}` errors.

  STARTTLS callers must own a passive binary/raw TCP socket, fully consume and
  validate the application's upgrade response, and reject any buffered plaintext.
  Supply `server_name_indication` as the certificate reference DNS name. Once
  upgrade is attempted, an owned socket is closed on failure; plaintext must
  never resume. A socket belonging to another process is left untouched.
  """
  import Kernel, except: [send: 2]
  alias SSL.{Connection, Options, Socket}

  @spec connect(:gen_tcp.socket(), list()) :: {:ok, Socket.t()} | {:error, term()}
  def connect(tcp_socket, options), do: connect(tcp_socket, options, :infinity)

  @spec connect(term(), term(), term()) :: {:ok, Socket.t()} | {:error, term()}
  def connect(host, port, options) when is_integer(port),
    do: connect(host, port, options, :infinity)

  def connect(tcp_socket, options, timeout) do
    with :ok <- owned_socket(tcp_socket) do
      result =
        with {:ok, deadline} <- Options.deadline(timeout),
             {:ok, options} <- Options.normalize(:upgrade, options),
             :ok <- upgrade_boundary(tcp_socket),
             do: handoff(tcp_socket, options, deadline)

      close_on_error(result, tcp_socket)
    end
  end

  @spec connect(term(), :inet.port_number(), list(), timeout()) ::
          {:ok, Socket.t()} | {:error, term()}
  def connect(host, port, options, timeout) when is_integer(port) and port in 0..65535 do
    with {:ok, deadline} <- Options.deadline(timeout),
         {:ok, options} <- Options.normalize(host, options),
         {:ok, _} <- Application.ensure_all_started(:ex_ssl),
         {:ok, tcp_socket} <-
           :gen_tcp.connect(
             tcp_host(host),
             port,
             [
               :binary,
               active: false,
               packet: :raw,
               send_timeout: 5_000,
               send_timeout_close: true,
               buffer: 16_640
             ],
             Options.remaining(deadline)
           ) do
      close_on_error(handoff(tcp_socket, options, deadline), tcp_socket)
    end
  catch
    :exit, _ -> {:error, :closed}
    :error, :badarg -> {:error, :badarg}
  end

  def connect(_, _, _, _), do: {:error, :badarg}

  @doc "Writes iodata once. A write is limited to 1 MiB; concurrent writes return `:busy`."
  @spec send(Socket.t(), iodata()) :: :ok | {:error, term()}
  def send(socket, data) do
    size = :erlang.iolist_size(data)

    if size > Connection.max_write_size() do
      {:error, :emsgsize}
    else
      with {:ok, token} <- call(socket, :reserve_write), do: call(socket, {:send, token, data})
    end
  rescue
    ArgumentError -> {:error, :badarg}
  end

  @doc "Receives available bytes for length 0, or exactly length bytes. Timeout retains buffered data."
  @spec recv(Socket.t(), non_neg_integer(), timeout()) :: {:ok, binary()} | {:error, term()}
  def recv(socket, length, timeout \\ :infinity)

  def recv(socket, length, timeout) when is_integer(length) and length >= 0 do
    with {:ok, deadline} <- Options.deadline(timeout), do: call(socket, {:recv, length, deadline})
  end

  def recv(_, _, _), do: {:error, :badarg}

  @doc "Closes the connection. Closing an already closed handle succeeds."
  @spec close(Socket.t()) :: :ok | {:error, term()}
  def close(%Socket{} = socket) do
    case call(socket, :close) do
      {:error, :closed} -> :ok
      {:error, :econnreset} -> :ok
      result -> result
    end
  end

  def close(_), do: {:error, :badarg}

  defp call(%Socket{pid: pid, ref: ref} = socket, request) do
    :gen_statem.call(pid, {ref, request}, :infinity)
  catch
    :exit, _ -> {:error, Socket.terminal_error(socket)}
  end

  defp call(_, _), do: {:error, :badarg}

  defp handoff(tcp, options, deadline) do
    with true <- Options.remaining(deadline) != 0,
         {:ok, _} <- Application.ensure_all_started(:ex_ssl) do
      ref = make_ref()
      status = :atomics.new(1, signed: false)

      case DynamicSupervisor.start_child(
             SSL.ConnectionSupervisor,
             {Connection, {self(), ref, status, options, deadline}}
           ) do
        {:ok, pid} ->
          socket = %Socket{pid: pid, ref: ref, status: status}

          case :gen_tcp.controlling_process(tcp, pid) do
            :ok ->
              call(socket, {:attach, tcp})

            {:error, reason} ->
              DynamicSupervisor.terminate_child(SSL.ConnectionSupervisor, pid)
              {:error, reason}
          end

        {:error, _} ->
          {:error, :closed}
      end
    else
      false -> {:error, :timeout}
      {:error, _} = error -> error
    end
  end

  defp owned_socket(socket) when is_port(socket) do
    case :erlang.port_info(socket, :connected) do
      {:connected, owner} when owner == self() -> :ok
      {:connected, _} -> {:error, :not_owner}
      nil -> {:error, :closed}
    end
  end

  defp owned_socket(_), do: {:error, :badarg}

  defp upgrade_boundary(tcp) do
    with {:ok, options} <- :inet.getopts(tcp, [:active, :packet, :mode]),
         true <-
           options[:active] == false and options[:packet] in [0, :raw] and
             options[:mode] == :binary,
         false <- delivered_tcp_message?(tcp) do
      case :gen_tcp.recv(tcp, 0, 0) do
        {:error, :timeout} -> :ok
        {:ok, _} -> {:error, :pending_plaintext}
        {:error, reason} -> {:error, reason}
      end
    else
      true -> {:error, :pending_plaintext}
      false -> {:error, {:options, :unsupported_tcp_state}}
      {:error, _} = error -> error
    end
  end

  defp delivered_tcp_message?(tcp) do
    {:messages, messages} = Process.info(self(), :messages)

    Enum.any?(messages, fn
      {:tcp, ^tcp, _} -> true
      {:tcp_closed, ^tcp} -> true
      {:tcp_error, ^tcp, _} -> true
      _ -> false
    end)
  end

  defp close_on_error({:error, _} = error, tcp) do
    :gen_tcp.close(tcp)
    error
  end

  defp close_on_error(result, _tcp), do: result
  defp tcp_host(host) when is_binary(host), do: String.to_charlist(host)
  defp tcp_host(host), do: host
end
