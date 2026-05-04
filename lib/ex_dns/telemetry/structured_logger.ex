defmodule ExDns.Telemetry.StructuredLogger do
  @moduledoc """
  Telemetry handler that emits one structured `Logger` line per
  catalogued ExDns event.

  Each line has the form `event=ex_dns.query.stop key=value ...` —
  trivially greppable, parseable by `logfmt` / Loki / Vector, and
  cheap to emit (no JSON encoder dependency).

  ## Wiring

  Production deployments typically attach this in their startup
  callback:

      ExDns.Telemetry.StructuredLogger.attach()

  When `:ex_dns, :structured_logs, [enabled: true]` is set the
  application supervisor attaches it automatically. The feature is
  off by default to keep the production footprint at zero until an
  operator opts in.

  ## Log fields

  Every line carries:

  * `event` — dotted form of the event name (e.g. `ex_dns.query.stop`).
  * `duration_us` — for `:stop`/`:exception` events, the elapsed time
    in microseconds. Omitted for instantaneous events.

  Plus the metadata declared for the event in `ExDns.Telemetry`:
  `transport`, `qname`, `qtype`, `rcode`, `validation`, `cache`,
  `client`, etc.
  """

  require Logger

  @handler_id "ex-dns-structured-logger"

  @doc """
  Attach the structured logger handler to every event in
  `ExDns.Telemetry.events/0`.

  ### Arguments

  * `handler_id` is the unique id under which the handler is
    registered with `:telemetry`. Defaults to
    `"ex-dns-structured-logger"`.

  ### Returns

  * `:ok` on success.

  * `{:error, :already_exists}` if a handler with the given id is
    already attached.

  ### Examples

      iex> ExDns.Telemetry.StructuredLogger.attach()
      :ok

  """
  @spec attach(term()) :: :ok | {:error, :already_exists}
  def attach(handler_id \\ @handler_id) do
    :telemetry.attach_many(
      handler_id,
      ExDns.Telemetry.events(),
      &__MODULE__.handle_event/4,
      %{}
    )
  end

  @doc """
  Detach the structured logger.

  ### Arguments

  * `handler_id` is the id under which the handler was attached.
    Defaults to `"ex-dns-structured-logger"`.

  ### Returns

  * `:ok` on success, or `{:error, :not_found}` if no handler with
    that id is currently attached.

  ### Examples

      iex> ExDns.Telemetry.StructuredLogger.attach("doctest-detach")
      iex> ExDns.Telemetry.StructuredLogger.detach("doctest-detach")
      :ok

  """
  @spec detach(term()) :: :ok | {:error, :not_found}
  def detach(handler_id \\ @handler_id) do
    :telemetry.detach(handler_id)
  end

  @doc false
  # Public so that :telemetry can resolve it by MFA across hot
  # code reloads. Not part of the API.
  def handle_event(event, measurements, metadata, _config) do
    fields =
      [{"event", event_name(event)}]
      |> add_duration(measurements)
      |> add_metadata(metadata)

    Logger.info(fn -> format_fields(fields) end)
  end

  defp event_name(event), do: event |> Enum.map(&Atom.to_string/1) |> Enum.join(".")

  defp add_duration(acc, %{duration: native}) when is_integer(native) do
    acc ++ [{"duration_us", System.convert_time_unit(native, :native, :microsecond)}]
  end

  defp add_duration(acc, _), do: acc

  # Metadata keys we know are useful and have stable cardinality.
  # Skips :stacktrace and other unbounded things; if a caller wants
  # those they can attach their own handler.
  @logged_metadata_keys [
    :transport,
    :qname,
    :qtype,
    :rcode,
    :answer_count,
    :validation,
    :cache,
    :status,
    :result,
    :key_name,
    :layer,
    :zone,
    :kind,
    :records,
    :bytes,
    :client,
    :kind,
    :reason
  ]

  defp add_metadata(acc, metadata) do
    extras =
      for key <- @logged_metadata_keys,
          Map.has_key?(metadata, key),
          do: {Atom.to_string(key), format_value(Map.fetch!(metadata, key))}

    acc ++ extras
  end

  defp format_value(nil), do: "-"
  defp format_value(atom) when is_atom(atom), do: Atom.to_string(atom)
  defp format_value(int) when is_integer(int), do: Integer.to_string(int)
  defp format_value({ip, port}) when is_tuple(ip) and (is_integer(port) or is_nil(port)) do
    "#{format_ip(ip)}:#{port || "-"}"
  end

  defp format_value(value) when is_binary(value) do
    if String.contains?(value, [" ", "=", "\""]) do
      ~s("#{String.replace(value, "\"", "\\\"")}")
    else
      value
    end
  end

  defp format_value(other), do: inspect(other)

  defp format_ip(ip) when is_tuple(ip) do
    case :inet.ntoa(ip) do
      {:error, _} -> inspect(ip)
      charlist -> List.to_string(charlist)
    end
  end

  defp format_fields(fields) do
    fields
    |> Enum.map(fn {k, v} -> "#{k}=#{v}" end)
    |> Enum.join(" ")
  end
end
