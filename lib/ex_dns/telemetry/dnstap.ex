defmodule ExDns.Telemetry.Dnstap do
  @moduledoc """
  dnstap exporter for ExDns.

  [dnstap](https://dnstap.info) is a structured DNS query/response
  log format defined as a Protocol Buffers schema. This module
  encodes the relevant subset of `dnstap.proto` directly with Elixir
  bitstrings — no `:protox` / `:protobuf` runtime dependency — and
  writes [Frame Streams](https://farsightsec.github.io/fstrm/)
  payloads to a file, which can later be replayed through
  `dnstap-read`, `dnscap`, or fed into a long-running `fstrm_replay`
  pipeline.

  ## Supported message types

  * `:auth_query` (CQ) — authoritative server received a query.
  * `:auth_response` (AR) — authoritative server sent a response.
  * `:client_query` (CQ-style; we use AQ) — issued during recursion.

  ## Wiring

  Attach the dnstap handler to a file sink:

      {:ok, sink} = ExDns.Telemetry.Dnstap.FileSink.start_link("/var/log/exdns.fstrm")
      ExDns.Telemetry.Dnstap.attach(sink)

  When `:ex_dns, :dnstap, [enabled: true, path: "/path/to/log"]` is
  set the application supervisor wires the sink + handler at
  startup. Off by default.

  ## Frame format

  The file is written as the **bidirectional Frame Streams**
  encoding (https://farsightsec.github.io/fstrm/spec.html), but
  with only **unidirectional** start/stop control frames since we
  only emit one direction. Each frame is `length::32-big, data` with
  control frames marked by `length=0` followed by an inner
  `control_length::32-big, control_payload`.
  """

  alias ExDns.Telemetry.Dnstap.{Encoder, FileSink}

  @handler_id "ex-dns-dnstap"

  @doc """
  Attach the dnstap handler to the named sink.

  ### Arguments

  * `sink` is a registered name or pid of a `FileSink` (or any
    process accepting `{:dnstap_payload, binary()}` casts).

  * `handler_id` is the unique id under which the handler is
    registered with `:telemetry`. Defaults to `"ex-dns-dnstap"`.

  ### Returns

  * `:ok` on success.

  * `{:error, :already_exists}` if a handler with the given id is
    already attached.

  ### Examples

      iex> {:ok, sink} = ExDns.Telemetry.Dnstap.FileSink.start_link(path: :memory)
      iex> ExDns.Telemetry.Dnstap.attach(sink)
      :ok

  """
  @spec attach(GenServer.server(), term()) :: :ok | {:error, :already_exists}
  def attach(sink, handler_id \\ @handler_id) do
    :telemetry.attach_many(
      handler_id,
      [
        [:ex_dns, :query, :start],
        [:ex_dns, :query, :stop]
      ],
      &__MODULE__.handle_event/4,
      %{sink: sink}
    )
  end

  @doc """
  Detach the dnstap handler.

  ### Arguments

  * `handler_id` defaults to `"ex-dns-dnstap"`.

  ### Returns

  * `:ok` or `{:error, :not_found}`.

  ### Examples

      iex> ExDns.Telemetry.Dnstap.detach("never-attached-id")
      {:error, :not_found}

  """
  @spec detach(term()) :: :ok | {:error, :not_found}
  def detach(handler_id \\ @handler_id) do
    :telemetry.detach(handler_id)
  end

  @doc false
  def handle_event([:ex_dns, :query, :start], _measurements, metadata, %{sink: sink}) do
    payload = Encoder.encode(:auth_query, metadata)
    FileSink.write(sink, payload)
  end

  def handle_event([:ex_dns, :query, :stop], _measurements, metadata, %{sink: sink}) do
    payload = Encoder.encode(:auth_response, metadata)
    FileSink.write(sink, payload)
  end
end
