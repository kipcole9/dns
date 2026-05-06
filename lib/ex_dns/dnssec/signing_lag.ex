defmodule ExDns.DNSSEC.SigningLag do
  @moduledoc """
  Tracks the wall-clock time of the most recent successful
  RRSIG generation per zone so operators can alert on
  signing lag.

  RRSIGs have an absolute expiration timestamp. If the
  signer falls behind — clock skew on the signer host,
  HSM outage, exhausted RNG, key store corruption — the
  next refresh window passes without new signatures, the
  old ones expire, and validating resolvers start
  returning SERVFAIL. The earlier you alert, the more
  recovery time you have before the lag becomes a public
  outage.

  ## Usage

  Every successful call to `ExDns.DNSSEC.Signer.sign_rrset/4`
  notes its zone via `observe/2`. Operators (or the
  Prometheus exporter) read `seconds_since_last_sign/1` and
  alert on a configurable threshold:

      iex> ExDns.DNSSEC.SigningLag.observe("example.com", 1_700_000_000)
      :ok

      iex> ExDns.DNSSEC.SigningLag.last_signed_at("example.com")
      1_700_000_000

  ## Telemetry

  Each `observe/2` emits

      [:ex_dns, :dnssec, :signed]

  with measurements `%{inception: integer}` and metadata
  `%{zone: binary}`. Hook into this from telemetry-metrics
  to publish a Prometheus gauge.
  """

  @table :ex_dns_dnssec_signing_lag

  @doc "Initialise the lag table. Idempotent."
  @spec init() :: :ok
  def init do
    case :ets.whereis(@table) do
      :undefined ->
        :ets.new(@table, [
          :set,
          :public,
          :named_table,
          read_concurrency: true,
          write_concurrency: true
        ])

        :ok

      _ ->
        :ok
    end
  end

  @doc """
  Record that `zone` was just signed with `inception` as
  its RRSIG inception timestamp. The most recent
  observation wins.
  """
  @spec observe(binary(), non_neg_integer()) :: :ok
  def observe(zone, inception) when is_binary(zone) and is_integer(inception) do
    init()
    :ets.insert(@table, {normalize(zone), inception})

    :telemetry.execute(
      [:ex_dns, :dnssec, :signed],
      %{inception: inception},
      %{zone: normalize(zone)}
    )

    :ok
  end

  @doc """
  Most recent observed inception timestamp for `zone`,
  or `nil` if no signature has been observed.
  """
  @spec last_signed_at(binary()) :: non_neg_integer() | nil
  def last_signed_at(zone) when is_binary(zone) do
    init()

    case :ets.lookup(@table, normalize(zone)) do
      [{_, inception}] -> inception
      [] -> nil
    end
  end

  @doc """
  Seconds elapsed between the most recent observed
  inception for `zone` and the configured `:now`. Returns
  `nil` when nothing has been observed yet.

  ### Options

  * `:now` — current time in seconds since the Unix epoch.
    Defaults to `System.os_time(:second)`. Override in
    tests.

  ### Examples

      iex> ExDns.DNSSEC.SigningLag.observe("ex.test", 100)
      iex> ExDns.DNSSEC.SigningLag.seconds_since_last_sign("ex.test", now: 250)
      150

  """
  @spec seconds_since_last_sign(binary(), keyword()) :: non_neg_integer() | nil
  def seconds_since_last_sign(zone, options \\ []) when is_binary(zone) do
    case last_signed_at(zone) do
      nil ->
        nil

      inception ->
        now = Keyword.get(options, :now, System.os_time(:second))
        max(now - inception, 0)
    end
  end

  @doc """
  Every observed zone with its lag (seconds since last
  signing). Useful for the metrics exporter.

  ### Returns

  * A list of `{zone_name, lag_seconds}` tuples.

  """
  @spec all_lags(keyword()) :: [{binary(), non_neg_integer()}]
  def all_lags(options \\ []) do
    init()
    now = Keyword.get(options, :now, System.os_time(:second))

    @table
    |> :ets.tab2list()
    |> Enum.map(fn {zone, inception} -> {zone, max(now - inception, 0)} end)
  end

  @doc false
  def reset do
    init()
    :ets.delete_all_objects(@table)
    :ok
  end

  defp normalize(name), do: name |> String.trim_trailing(".") |> String.downcase(:ascii)
end
