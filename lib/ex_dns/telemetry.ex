defmodule ExDns.Telemetry do
  @moduledoc """
  Catalogue of every `:telemetry` event emitted by ExDns and helpers
  for attaching default handlers.

  This module is the single source of truth for event names and the
  shape of their measurements/metadata. Subsystems that wish to react
  to ExDns activity — Prometheus metrics, structured logs, dnstap
  exporters, downstream tracing — all consume the same event stream
  declared here.

  ## Event naming convention

  All events are namespaced under `[:ex_dns, ...]` and follow the
  conventional `:start` / `:stop` / `:exception` triplet for spans, or
  a single atom (e.g. `:hit`) for instantaneous events. `:stop` events
  carry a `:duration` measurement (native time units) where applicable.

  ## Events

  ### Query lifecycle

  * `[:ex_dns, :query, :start]` — a request entered the resolver.

      * Measurements: `%{system_time: integer()}`
      * Metadata: `%{transport: :udp | :tcp | :doh, qname: String.t(),
        qtype: atom(), client: tuple()}`

  * `[:ex_dns, :query, :stop]` — a response is about to be sent.

      * Measurements: `%{duration: integer()}`
      * Metadata: `%{transport: :udp | :tcp | :doh, qname: String.t(),
        qtype: atom(), rcode: atom(), answer_count: integer(),
        cache: :hit | :miss | :none, validation: validation_status()}`

  * `[:ex_dns, :query, :exception]` — request failed unexpectedly.

      * Measurements: `%{duration: integer()}`
      * Metadata: `%{kind: atom(), reason: term(), stacktrace: list()}`

  ### Cache

  * `[:ex_dns, :cache, :hit]` / `[:ex_dns, :cache, :miss]` —
    cache lookup outcome.

      * Measurements: `%{count: 1}`
      * Metadata: `%{layer: :recursor | :authoritative,
        qname: String.t(), qtype: atom()}`

  ### DNSSEC validation

  * `[:ex_dns, :dnssec, :validate, :stop]` — chain validation finished.

      * Measurements: `%{duration: integer()}`
      * Metadata: `%{qname: String.t(), qtype: atom(),
        status: validation_status()}`

  ### TSIG

  * `[:ex_dns, :tsig, :verify, :stop]` — TSIG verification result on
    an inbound message.

      * Measurements: `%{duration: integer()}`
      * Metadata: `%{key_name: String.t(), result: :ok | :bad_sig |
        :bad_key | :bad_time}`

  ### AXFR / IXFR

  * `[:ex_dns, :axfr, :transfer, :start]` — outbound transfer began.

      * Measurements: `%{system_time: integer()}`
      * Metadata: `%{zone: String.t(), peer: tuple(), kind: :axfr | :ixfr}`

  * `[:ex_dns, :axfr, :transfer, :stop]` — outbound transfer finished.

      * Measurements: `%{duration: integer(), records: integer(),
        bytes: integer()}`
      * Metadata: `%{zone: String.t(), peer: tuple(), kind: :axfr | :ixfr,
        result: :ok | {:error, term()}}`

  ### Cluster

  * `[:ex_dns, :cluster, :master, :elected]` — this node became master
    for a zone.

      * Measurements: `%{count: 1}`
      * Metadata: `%{zone: String.t()}`

  ## Validation status

  Wherever metadata declares `validation_status()`, the value is one
  of `:secure`, `:insecure`, `:bogus`, `:indeterminate`, or `:none`
  (the last meaning DNSSEC was not consulted at all, e.g. CD=1 or
  authoritative non-DNSSEC zone).

  ## Default handlers

  `default_handlers/0` returns a list of `{handler_id, event_name,
  fun}` triples suitable for `:telemetry.attach_many/4`. Production
  deployments typically replace these with metric-emitting handlers
  registered by `ExDns.Metrics`.
  """

  require Logger

  @typedoc "Possible DNSSEC validation outcomes carried in metadata."
  @type validation_status ::
          :secure | :insecure | :bogus | :indeterminate | :none

  @doc """
  Returns every event name ExDns may emit.

  ### Returns

  * A list of event names. Each element is a list of atoms suitable
    for use with `:telemetry.attach/4`.

  ### Examples

      iex> [:ex_dns, :query, :stop] in ExDns.Telemetry.events()
      true

  """
  @spec events() :: [[atom()]]
  def events do
    [
      [:ex_dns, :query, :start],
      [:ex_dns, :query, :stop],
      [:ex_dns, :query, :exception],
      [:ex_dns, :cache, :hit],
      [:ex_dns, :cache, :miss],
      [:ex_dns, :dnssec, :validate, :stop],
      [:ex_dns, :tsig, :verify, :stop],
      [:ex_dns, :axfr, :transfer, :start],
      [:ex_dns, :axfr, :transfer, :stop],
      [:ex_dns, :cluster, :master, :elected],
      [:ex_dns, :drain, :start],
      [:ex_dns, :drain, :stop],
      [:ex_dns, :rrl, :decision],
      [:ex_dns, :notify, :sent],
      [:ex_dns, :transfer, :acl, :decision],
      [:ex_dns, :secondary, :loaded],
      [:ex_dns, :secondary, :transfer_failed],
      [:ex_dns, :zone, :reload, :stop],
      [:ex_dns, :catalog, :reconcile],
      [:ex_dns, :dnssec, :rollover, :prepared],
      [:ex_dns, :dnssec, :rollover, :activated],
      [:ex_dns, :dnssec, :rollover, :purged]
    ]
  end

  @doc """
  Attach a debug-level Logger handler to every ExDns telemetry event.

  Useful during development; in production prefer `ExDns.Metrics`.

  ### Arguments

  * `handler_id` is the unique id under which the handler is
    registered with `:telemetry`. Defaults to `"ex-dns-default-log"`.

  ### Returns

  * `:ok` on success.

  * `{:error, :already_exists}` if a handler with the given id is
    already attached.

  ### Examples

      iex> ExDns.Telemetry.attach_default_logger()
      :ok

  """
  @spec attach_default_logger(term()) :: :ok | {:error, :already_exists}
  def attach_default_logger(handler_id \\ "ex-dns-default-log") do
    :telemetry.attach_many(handler_id, events(), &__MODULE__.handle_event/4, %{})
  end

  @doc false
  # Default handler — emits a single debug log line per event. Public
  # because :telemetry requires module-function-arity to be reachable
  # for hot-code reloading; not part of the API.
  def handle_event(event, measurements, metadata, _config) do
    Logger.debug(fn ->
      "[telemetry] #{Enum.join(event, ".")} measurements=#{inspect(measurements)} metadata=#{inspect(metadata)}"
    end)
  end
end
