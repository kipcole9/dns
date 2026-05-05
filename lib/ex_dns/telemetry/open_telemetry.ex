defmodule ExDns.Telemetry.OpenTelemetry do
  @moduledoc """
  OpenTelemetry tracing bridge: maps the telemetry events emitted
  by ExDns into OTel spans.

  Each `[:ex_dns, :query, :start]` opens a `dns.query` span with
  the qname/qtype/transport on it as attributes. The matching
  `:stop` closes the span and records the rcode and answer count.
  `:exception` records the exception on the span before closing.

  ## Optional dependency

  `:opentelemetry_api` is declared as an `optional: true`
  runtime dep. Operators who want tracing pull in
  `:opentelemetry` (the SDK) and an exporter
  (`:opentelemetry_exporter`, `:opentelemetry_zipkin`, etc.) in
  their *own* mix.exs. Without those, this bridge silently no-ops
  — the `attach/0` call returns `{:error, :otel_not_loaded}` and
  no events are intercepted.

  ## Wiring

      ExDns.Telemetry.OpenTelemetry.attach()

  Or via application config:

      config :ex_dns, :open_telemetry, enabled: true

  When the config flag is set, `ExDns.Application` calls
  `attach/0` automatically after the supervisor comes up.
  """

  require OpenTelemetry.Tracer

  @handler_id "ex-dns-open-telemetry"

  # Process-dictionary key for the currently-open span. Spans are
  # owned by the process that handled the :start event; the same
  # process handles the :stop, so a single key per process is
  # enough.
  @span_key {__MODULE__, :current_span}

  @doc """
  Attach the OpenTelemetry handler to ExDns query events.

  ### Returns

  * `:ok` on success.

  * `{:error, :already_exists}` if a handler with this id is
    already attached.

  * `{:error, :otel_not_loaded}` when the optional
    `:opentelemetry_api` dep isn't available at runtime.

  ### Examples

      iex> ExDns.Telemetry.OpenTelemetry.attach() in
      ...>   [:ok, {:error, :already_exists}, {:error, :otel_not_loaded}]
      true

  """
  @spec attach(term()) :: :ok | {:error, :already_exists | :otel_not_loaded}
  def attach(handler_id \\ @handler_id) do
    if Code.ensure_loaded?(:otel_tracer) do
      :telemetry.attach_many(
        handler_id,
        [
          [:ex_dns, :query, :start],
          [:ex_dns, :query, :stop],
          [:ex_dns, :query, :exception]
        ],
        &__MODULE__.handle_event/4,
        %{}
      )
    else
      {:error, :otel_not_loaded}
    end
  end

  @doc """
  Detach the handler.

  ### Arguments

  * `handler_id` — defaults to the canonical handler id.

  ### Returns

  * `:ok` or `{:error, :not_found}`.

  ### Examples

      iex> ExDns.Telemetry.OpenTelemetry.detach("never-attached")
      {:error, :not_found}

  """
  @spec detach(term()) :: :ok | {:error, :not_found}
  def detach(handler_id \\ @handler_id) do
    :telemetry.detach(handler_id)
  end

  @doc false
  def handle_event([:ex_dns, :query, :start], _measurements, metadata, _config) do
    span_ctx =
      OpenTelemetry.Tracer.start_span(
        "dns.query",
        %{
          attributes:
            attribute_pairs(metadata,
              ~w[transport qname qtype client]a
            ),
          kind: :server
        }
      )

    Process.put(@span_key, span_ctx)
    :ok
  end

  def handle_event([:ex_dns, :query, :stop], measurements, metadata, _config) do
    case Process.delete(@span_key) do
      nil ->
        :ok

      span_ctx ->
        OpenTelemetry.Span.set_attributes(
          span_ctx,
          attribute_pairs(metadata, ~w[rcode answer_count cache validation]a) ++
            duration_attribute(measurements)
        )

        OpenTelemetry.Span.end_span(span_ctx)
        :ok
    end
  end

  def handle_event([:ex_dns, :query, :exception], _measurements, metadata, _config) do
    case Process.delete(@span_key) do
      nil ->
        :ok

      span_ctx ->
        OpenTelemetry.Span.record_exception(
          span_ctx,
          Map.get(metadata, :reason, :unknown),
          Map.get(metadata, :stacktrace, [])
        )

        OpenTelemetry.Span.set_status(span_ctx, OpenTelemetry.status(:error, "exception"))
        OpenTelemetry.Span.end_span(span_ctx)
        :ok
    end
  end

  # ----- helpers ----------------------------------------------------

  defp attribute_pairs(metadata, keys) do
    for key <- keys,
        Map.has_key?(metadata, key),
        do: {key, format_attribute(Map.get(metadata, key))}
  end

  defp duration_attribute(%{duration: native}) when is_integer(native) do
    [{:"duration.us", System.convert_time_unit(native, :native, :microsecond)}]
  end

  defp duration_attribute(_), do: []

  defp format_attribute(value) when is_atom(value) and not is_nil(value),
    do: Atom.to_string(value)

  defp format_attribute(value) when is_binary(value) or is_integer(value), do: value

  defp format_attribute({ip, port}) when is_tuple(ip) do
    case :inet.ntoa(ip) do
      {:error, _} -> inspect({ip, port})
      charlist -> "#{List.to_string(charlist)}:#{port || 0}"
    end
  end

  defp format_attribute(other), do: inspect(other)
end
