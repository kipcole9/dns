defmodule ExDns.Zone.Secondary do
  @moduledoc """
  `gen_statem`-based state machine that owns one secondary zone,
  pulling copies from configured primaries on schedule and on
  NOTIFY.

  ## States

  * `:initial` — never loaded. Tries AXFR on entry; stays in
    `:initial` and retries on failure; transitions to `:loaded`
    on success.

  * `:loaded` — have a current copy. Periodic SOA query on the
    primary; pulls AXFR when the serial advances. Falls back to
    `:initial` and discards the zone when the RFC 1035 §3.3.13
    expire window elapses without a successful contact.

  ## Events

  * State timeout `:tick` — fires the next scheduled refresh or
    retry. Schedule lengths come from the zone's SOA fields
    (`refresh`, `retry`, `expire`); for the initial pull, from
    the `:initial_*` config keys (defaults: 60s refresh, 30s
    retry, 86400s expire).

  * Cast `:refresh_now` — external trigger from `notify/1`
    (called by the NOTIFY-receiver path or operators).

  ## Storage interaction

  Successful loads call `ExDns.Storage.put_zone/2`, which writes
  the IXFR journal entry, fires NOTIFY to *its* secondaries,
  etc. The state machine doesn't bypass the normal storage path.

  ## Wiring

  Configure a list of secondary zones; the application supervisor
  starts one of these state machines per entry under
  `ExDns.Zone.Secondary.Supervisor`:

      config :ex_dns, :secondary_zones, [
        %{
          apex: "example.test",
          primaries: [{{192, 0, 2, 1}, 53}],
          initial_refresh_seconds: 30,
          initial_retry_seconds: 10,
          initial_expire_seconds: 86_400
        }
      ]
  """

  @behaviour :gen_statem

  require Logger

  alias ExDns.Resource.SOA
  alias ExDns.Storage
  alias ExDns.Zone.Secondary.Client

  @default_initial_refresh 60
  @default_initial_retry 30
  @default_initial_expire 86_400

  defstruct apex: nil,
            primaries: [],
            soa: nil,
            last_success: nil,
            tsig_key: nil,
            initial_refresh: @default_initial_refresh,
            initial_retry: @default_initial_retry,
            initial_expire: @default_initial_expire

  @type state :: :initial | :loaded
  @type data :: %__MODULE__{
          apex: binary(),
          primaries: [{tuple(), pos_integer()}],
          soa: SOA.t() | nil,
          last_success: integer() | nil,
          initial_refresh: pos_integer(),
          initial_retry: pos_integer(),
          initial_expire: pos_integer()
        }

  # ----- public API -------------------------------------------------

  @doc """
  Start a secondary-zone manager.

  ### Arguments

  * `config` is a map with at minimum `:apex` and `:primaries`.

  ### Returns

  * `{:ok, pid}` on success, `{:error, reason}` otherwise.
  """
  @spec start_link(map()) :: :gen_statem.start_ret()
  def start_link(%{apex: apex} = config) when is_binary(apex) do
    :gen_statem.start_link({:local, name(apex)}, __MODULE__, config, [])
  end

  @doc false
  def child_spec(%{apex: apex} = config) do
    %{
      id: {__MODULE__, apex},
      start: {__MODULE__, :start_link, [config]},
      type: :worker,
      restart: :permanent,
      shutdown: 5_000
    }
  end

  @doc """
  Trigger an immediate refresh. Used by the NOTIFY receiver and
  by operators forcing a re-pull.

  ### Arguments

  * `apex` is the zone apex (binary).

  ### Returns

  * `:ok` if a manager is running for `apex`.
  * `{:error, :no_secondary_for_zone}` otherwise.

  ### Examples

      iex> ExDns.Zone.Secondary.notify("nope.test")
      {:error, :no_secondary_for_zone}

  """
  @spec notify(binary()) :: :ok | {:error, :no_secondary_for_zone}
  def notify(apex) when is_binary(apex) do
    case Process.whereis(name(apex)) do
      nil -> {:error, :no_secondary_for_zone}
      pid -> :gen_statem.cast(pid, :refresh_now)
    end
  end

  @doc """
  Return the current state and data tuple for `apex`. Used by
  tests and the readiness check.

  ### Arguments

  * `apex` is the zone apex.

  ### Returns

  * `{state_name, data}` when a manager is running.
  * `nil` when no manager exists for that apex.
  """
  @spec snapshot(binary()) :: {state(), data()} | nil
  def snapshot(apex) do
    case Process.whereis(name(apex)) do
      nil -> nil
      pid -> :sys.get_state(pid)
    end
  end

  defp name(apex), do: Module.concat(__MODULE__, normalise(apex))

  # ----- gen_statem callbacks --------------------------------------

  @impl :gen_statem
  def callback_mode, do: :state_functions

  @impl :gen_statem
  def init(config) do
    data = %__MODULE__{
      apex: normalise(config.apex),
      primaries: Map.get(config, :primaries, []),
      tsig_key: Map.get(config, :tsig_key),
      initial_refresh: Map.get(config, :initial_refresh_seconds, @default_initial_refresh),
      initial_retry: Map.get(config, :initial_retry_seconds, @default_initial_retry),
      initial_expire: Map.get(config, :initial_expire_seconds, @default_initial_expire)
    }

    # Kick the first AXFR shortly after startup so the supervision
    # tree finishes coming up before we touch the network.
    {:ok, :initial, data, [tick_in(100)]}
  end

  # ----- :initial state --------------------------------------------

  @doc false
  def initial(:state_timeout, :tick, data), do: try_initial_load(data)
  def initial(:cast, :refresh_now, data), do: try_initial_load(data)
  def initial(_event_type, _content, data), do: {:keep_state, data}

  defp try_initial_load(%__MODULE__{apex: apex, primaries: primaries} = data) do
    Logger.info("ExDns.Zone.Secondary[#{apex}]: initial AXFR from #{inspect(primaries)}")

    case axfr_from_any(primaries, apex, data.tsig_key) do
      {:ok, records, %SOA{} = soa} ->
        Storage.put_zone(apex, records)
        ExDns.Zone.Snapshot.Writer.request()

        :telemetry.execute(
          [:ex_dns, :secondary, :loaded],
          %{count: 1},
          %{zone: apex, serial: soa.serial, kind: :axfr}
        )

        loaded_data = %__MODULE__{
          data
          | soa: soa,
            last_success: System.monotonic_time(:second)
        }

        {:next_state, :loaded, loaded_data, [tick_in(soa.refresh * 1_000)]}

      {:error, reason} ->
        Logger.warning("ExDns.Zone.Secondary[#{apex}]: initial AXFR failed: #{inspect(reason)}")

        :telemetry.execute(
          [:ex_dns, :secondary, :transfer_failed],
          %{count: 1},
          %{zone: apex, reason: reason, kind: :axfr}
        )

        {:keep_state, data, [tick_in(data.initial_retry * 1_000)]}
    end
  end

  # ----- :loaded state ---------------------------------------------

  @doc false
  def loaded(:state_timeout, :tick, data), do: refresh_loaded(data)
  def loaded(:cast, :refresh_now, data), do: refresh_loaded(data)
  def loaded(_event_type, _content, data), do: {:keep_state, data}

  defp refresh_loaded(%__MODULE__{apex: apex, primaries: primaries, soa: %SOA{} = current} = data) do
    case soa_from_any(primaries, apex, data.tsig_key) do
      {:ok, %SOA{serial: primary_serial}} when primary_serial == current.serial ->
        Logger.debug("ExDns.Zone.Secondary[#{apex}]: serial unchanged (#{primary_serial})")
        {:keep_state, data, [tick_in(current.refresh * 1_000)]}

      {:ok, %SOA{serial: primary_serial}} ->
        Logger.info(
          "ExDns.Zone.Secondary[#{apex}]: serial advanced #{current.serial} → #{primary_serial}, pulling AXFR"
        )

        case axfr_from_any(primaries, apex, data.tsig_key) do
          {:ok, records, new_soa} ->
            Storage.put_zone(apex, records)
            ExDns.Zone.Snapshot.Writer.request()

            :telemetry.execute(
              [:ex_dns, :secondary, :loaded],
              %{count: 1},
              %{zone: apex, serial: new_soa.serial, kind: :axfr}
            )

            new_data = %__MODULE__{
              data
              | soa: new_soa,
                last_success: System.monotonic_time(:second)
            }

            {:keep_state, new_data, [tick_in(new_soa.refresh * 1_000)]}

          {:error, reason} ->
            Logger.warning(
              "ExDns.Zone.Secondary[#{apex}]: AXFR after serial advance failed: #{inspect(reason)}"
            )

            {:keep_state, data, [tick_in(current.retry * 1_000)]}
        end

      {:error, reason} ->
        Logger.warning("ExDns.Zone.Secondary[#{apex}]: SOA query failed: #{inspect(reason)}")

        :telemetry.execute(
          [:ex_dns, :secondary, :transfer_failed],
          %{count: 1},
          %{zone: apex, reason: reason, kind: :soa}
        )

        # RFC 1035 §3.3.13: discard the zone if no successful
        # contact for `expire` seconds.
        if expired?(data) do
          Logger.warning(
            "ExDns.Zone.Secondary[#{apex}]: expire window elapsed — discarding zone"
          )

          Storage.delete_zone(apex)

          {:next_state, :initial, %__MODULE__{data | soa: nil},
           [tick_in(data.initial_retry * 1_000)]}
        else
          {:keep_state, data, [tick_in(current.retry * 1_000)]}
        end
    end
  end

  # ----- helpers ----------------------------------------------------

  defp expired?(%__MODULE__{soa: %SOA{expire: expire}, last_success: last}) when is_integer(last) do
    System.monotonic_time(:second) - last > expire
  end

  defp expired?(_), do: false

  defp axfr_from_any([], _apex, _key), do: {:error, :no_primaries}

  defp axfr_from_any([primary | rest], apex, tsig_key) do
    case Client.fetch_axfr(apex, primary, client_options(tsig_key)) do
      {:ok, records} ->
        case Enum.find(records, &match?(%SOA{}, &1)) do
          %SOA{} = soa -> {:ok, records, soa}
          _ -> {:error, :no_soa_in_axfr}
        end

      {:error, reason} ->
        if rest == [], do: {:error, reason}, else: axfr_from_any(rest, apex, tsig_key)
    end
  end

  defp soa_from_any([], _apex, _key), do: {:error, :no_primaries}

  defp soa_from_any([primary | rest], apex, tsig_key) do
    case Client.fetch_soa(apex, primary, client_options(tsig_key)) do
      {:ok, %SOA{}} = ok -> ok
      {:error, _} when rest != [] -> soa_from_any(rest, apex, tsig_key)
      {:error, _} = err -> err
    end
  end

  defp client_options(nil), do: []
  defp client_options(key) when is_binary(key), do: [tsig_key: key]

  defp tick_in(delay_ms) when is_integer(delay_ms) and delay_ms >= 0 do
    {:state_timeout, delay_ms, :tick}
  end

  defp normalise(name) when is_binary(name) do
    name |> String.trim_trailing(".") |> String.downcase(:ascii)
  end
end
