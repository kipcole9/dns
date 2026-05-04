defmodule ExDns.Telemetry.Dnstap.FileSink do
  @moduledoc """
  GenServer that writes dnstap payloads to a file using
  [Frame Streams](https://farsightsec.github.io/fstrm/spec.html)
  unidirectional framing.

  ## File format

  A unidirectional fstrm stream begins with two control frames:

      START control frame: <<0::32>> <<control_length::32>> <<control_payload::binary>>

  followed by one or more data frames:

      data frame: <<length::32>> <<payload::binary>>

  and is terminated by a STOP control frame on close.

  The control payload includes a `CONTENT_TYPE` field whose value
  identifies the consumer; for dnstap the agreed string is
  `"protobuf:dnstap.Dnstap"`.

  ## Modes

  * `:file` — the default. Writes to a path, flushed on every
    payload (use `O_APPEND`-style semantics so concurrent ExDns
    nodes can share a path safely).

  * `:memory` — buffers writes in process state. Useful for tests
    and ad-hoc inspection. `flush_buffer/1` returns the accumulated
    bytes.
  """

  use GenServer

  @content_type "protobuf:dnstap.Dnstap"

  # Frame Streams control frame types
  @control_start 0x01
  @control_stop 0x03

  # Control field types
  @field_content_type 0x01

  # ----- public API -----

  @doc """
  Start the sink.

  ### Arguments

  * `path` is either a filesystem path (binary), the atom `:memory`
    for an in-memory buffer, or a keyword list of options:

  ### Options

  * `:path` — `:memory` or a filesystem path. Required.
  * `:name` — optional registered process name.

  ### Returns

  * `{:ok, pid}` on success, `{:error, reason}` otherwise.

  ### Examples

      iex> {:ok, pid} = ExDns.Telemetry.Dnstap.FileSink.start_link(path: :memory)
      iex> is_pid(pid)
      true

  """
  @spec start_link(binary() | :memory | keyword()) :: GenServer.on_start()
  def start_link(arg)

  def start_link(path) when is_binary(path) or path == :memory do
    GenServer.start_link(__MODULE__, %{path: path})
  end

  def start_link(options) when is_list(options) do
    path = Keyword.fetch!(options, :path)
    name = Keyword.get(options, :name)

    case name do
      nil -> GenServer.start_link(__MODULE__, %{path: path})
      name -> GenServer.start_link(__MODULE__, %{path: path}, name: name)
    end
  end

  @doc """
  Write a single dnstap payload through the sink. The sink wraps it
  in a Frame Streams data frame.

  ### Arguments

  * `sink` is the registered name or pid of a `FileSink`.
  * `payload` is a binary (a complete dnstap envelope).

  ### Returns

  * `:ok`.

  ### Examples

      iex> {:ok, sink} = ExDns.Telemetry.Dnstap.FileSink.start_link(path: :memory)
      iex> ExDns.Telemetry.Dnstap.FileSink.write(sink, "hello")
      :ok

  """
  @spec write(GenServer.server(), binary()) :: :ok
  def write(sink, payload) when is_binary(payload) do
    GenServer.cast(sink, {:write, payload})
  end

  @doc """
  Returns the bytes accumulated so far when running in `:memory` mode.

  ### Arguments

  * `sink` is the registered name or pid of a `FileSink` started with
    `path: :memory`.

  ### Returns

  * The accumulated buffer as a binary.

  * Returns `:not_in_memory_mode` if the sink is backed by a file.

  ### Examples

      iex> {:ok, sink} = ExDns.Telemetry.Dnstap.FileSink.start_link(path: :memory)
      iex> ExDns.Telemetry.Dnstap.FileSink.flush_buffer(sink) |> is_binary()
      true

  """
  @spec flush_buffer(GenServer.server()) :: binary() | :not_in_memory_mode
  def flush_buffer(sink) do
    GenServer.call(sink, :flush_buffer)
  end

  # ----- GenServer callbacks -----

  @impl true
  def init(%{path: :memory}) do
    state = %{path: :memory, file: nil, buffer: start_frame()}
    {:ok, state}
  end

  def init(%{path: path}) when is_binary(path) do
    case File.open(path, [:append, :binary]) do
      {:ok, file} ->
        IO.binwrite(file, start_frame())
        {:ok, %{path: path, file: file, buffer: nil}}

      {:error, reason} ->
        {:stop, {:cannot_open, path, reason}}
    end
  end

  @impl true
  def handle_cast({:write, payload}, %{path: :memory, buffer: buffer} = state) do
    {:noreply, %{state | buffer: buffer <> data_frame(payload)}}
  end

  def handle_cast({:write, payload}, %{file: file} = state) when is_pid(file) or is_port(file) do
    IO.binwrite(file, data_frame(payload))
    {:noreply, state}
  end

  @impl true
  def handle_call(:flush_buffer, _from, %{path: :memory, buffer: buffer} = state) do
    {:reply, buffer, state}
  end

  def handle_call(:flush_buffer, _from, state) do
    {:reply, :not_in_memory_mode, state}
  end

  @impl true
  def terminate(_reason, %{file: nil}), do: :ok

  def terminate(_reason, %{file: file}) do
    try do
      IO.binwrite(file, stop_frame())
      File.close(file)
    catch
      _, _ -> :ok
    end

    :ok
  end

  # ----- frame helpers -----

  # Data frame: <<length::32-big, payload::binary>>
  defp data_frame(payload) do
    <<byte_size(payload)::32-big, payload::binary>>
  end

  # Control frame: <<0::32-big, ctrl_length::32-big, ctrl_type::32-big, fields::binary>>
  # START control frame includes a CONTENT_TYPE field.
  defp start_frame do
    inner =
      <<@control_start::32-big>> <>
        <<@field_content_type::32-big, byte_size(@content_type)::32-big, @content_type::binary>>

    <<0::32-big, byte_size(inner)::32-big, inner::binary>>
  end

  defp stop_frame do
    inner = <<@control_stop::32-big>>
    <<0::32-big, byte_size(inner)::32-big, inner::binary>>
  end
end
