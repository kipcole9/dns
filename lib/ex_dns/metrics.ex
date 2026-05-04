defmodule ExDns.Metrics do
  @moduledoc """
  Prometheus metric definitions for ExDns.

  This module declares the `Telemetry.Metrics` collected from the
  events catalogued in `ExDns.Telemetry`, and exposes a `child_spec/1`
  that runs `TelemetryMetricsPrometheus` under the application
  supervision tree. The exporter publishes a `/metrics` endpoint on a
  configurable port (defaults to 9568) suitable for scraping by a
  Prometheus server.

  ## Metrics

  * `dns_queries_total` (counter) — every query observed, tagged by
    `transport`, `qtype`, and `rcode`.

  * `dns_query_duration_microseconds` (distribution) — end-to-end
    latency from request decode to response send, tagged by
    `transport`.

  * `dns_cache_hits_total` / `dns_cache_misses_total` (counters) —
    cache lookup outcomes, tagged by `layer`.

  * `dns_dnssec_validations_total` (counter) — chain validation
    outcomes, tagged by `status`.

  * `dns_tsig_verifications_total` (counter) — TSIG verification
    outcomes, tagged by `result`.

  * `dns_axfr_transfers_total` (counter) — AXFR/IXFR transfers
    completed, tagged by `kind` and `result`.

  * `dns_cluster_master_elections_total` (counter) — number of times
    this node became master, tagged by `zone`.

  ## Configuration

  ```elixir
  config :ex_dns, :metrics,
    enabled: true,
    port: 9568
  ```

  When `:enabled` is `false` (the default while the metrics surface
  bakes), neither the Prometheus exporter nor the metric handlers are
  registered. This keeps the production footprint zero until an
  operator opts in.
  """

  import Telemetry.Metrics

  @doc """
  Build a child spec for the Prometheus exporter.

  ### Arguments

  * `options` is a keyword list. Recognised keys:

  ### Options

  * `:port` — the TCP port the `/metrics` endpoint binds to.
    Defaults to `9568`.

  * `:name` — registered name for the underlying `:telemetry_handler`
    table. Defaults to `:ex_dns_prometheus`.

  ### Returns

  * A child spec map suitable for inclusion in a `Supervisor` child
    list.

  ### Examples

      iex> spec = ExDns.Metrics.child_spec(port: 9999)
      iex> spec.id
      TelemetryMetricsPrometheus

  """
  @spec child_spec(keyword()) :: Supervisor.child_spec()
  def child_spec(options \\ []) do
    port = Keyword.get(options, :port, 9568)
    name = Keyword.get(options, :name, :ex_dns_prometheus)

    {TelemetryMetricsPrometheus,
     [
       metrics: metrics(),
       port: port,
       name: name
     ]}
    |> Supervisor.child_spec(id: TelemetryMetricsPrometheus)
  end

  @doc """
  Returns the canonical list of `Telemetry.Metrics` definitions
  emitted to the Prometheus registry.

  ### Returns

  * A list of `Telemetry.Metrics` structs (Counter, Distribution,
    etc.) that map ExDns telemetry events to Prometheus metric
    names, tags, and reporter-specific options.

  ### Examples

      iex> ExDns.Metrics.metrics() |> Enum.map(& &1.name) |> Enum.member?([:dns, :queries, :total])
      true

  """
  @spec metrics() :: [Telemetry.Metrics.t()]
  def metrics do
    [
      counter(
        "dns.queries.total",
        event_name: [:ex_dns, :query, :stop],
        description: "Total DNS queries answered, tagged by transport, qtype and rcode.",
        tags: [:transport, :qtype, :rcode],
        tag_values: &normalise_query_tags/1
      ),
      distribution(
        "dns.query.duration.microseconds",
        event_name: [:ex_dns, :query, :stop],
        measurement: &duration_microseconds/2,
        description: "End-to-end resolver duration in microseconds.",
        tags: [:transport],
        tag_values: &normalise_query_tags/1,
        reporter_options: [
          buckets: [50, 100, 250, 500, 1_000, 2_500, 5_000, 10_000, 25_000, 50_000, 100_000]
        ],
        unit: :native
      ),
      counter(
        "dns.cache.hits.total",
        event_name: [:ex_dns, :cache, :hit],
        description: "Cache lookups that hit, tagged by layer.",
        tags: [:layer]
      ),
      counter(
        "dns.cache.misses.total",
        event_name: [:ex_dns, :cache, :miss],
        description: "Cache lookups that missed, tagged by layer.",
        tags: [:layer]
      ),
      counter(
        "dns.dnssec.validations.total",
        event_name: [:ex_dns, :dnssec, :validate, :stop],
        description: "DNSSEC chain validation outcomes.",
        tags: [:status]
      ),
      counter(
        "dns.tsig.verifications.total",
        event_name: [:ex_dns, :tsig, :verify, :stop],
        description: "TSIG verification outcomes.",
        tags: [:result]
      ),
      counter(
        "dns.axfr.transfers.total",
        event_name: [:ex_dns, :axfr, :transfer, :stop],
        description: "AXFR/IXFR transfers completed.",
        tags: [:kind, :result],
        tag_values: &normalise_axfr_tags/1
      ),
      counter(
        "dns.cluster.master.elections.total",
        event_name: [:ex_dns, :cluster, :master, :elected],
        description: "Number of times this node was elected master.",
        tags: [:zone]
      )
    ]
  end

  # Coerce free-form metadata to a stable tag set. Prometheus tag
  # values must be strings/atoms with bounded cardinality; rcode
  # comes through as an integer or atom depending on caller.
  @doc false
  def normalise_query_tags(metadata) do
    %{
      transport: Map.get(metadata, :transport, :unknown),
      qtype: Map.get(metadata, :qtype, :unknown),
      rcode: stringify_rcode(Map.get(metadata, :rcode))
    }
  end

  @doc false
  def normalise_axfr_tags(metadata) do
    result =
      case Map.get(metadata, :result) do
        :ok -> :ok
        {:error, _} -> :error
        other -> other
      end

    %{
      kind: Map.get(metadata, :kind, :axfr),
      result: result
    }
  end

  defp stringify_rcode(rcode) when is_atom(rcode), do: rcode
  defp stringify_rcode(rcode) when is_integer(rcode), do: Integer.to_string(rcode)
  defp stringify_rcode(_), do: "unknown"

  defp duration_microseconds(%{duration: native}, _metadata) do
    System.convert_time_unit(native, :native, :microsecond)
  end

  defp duration_microseconds(_, _), do: 0
end
