defmodule ExDns.Zone.Catalog.Subscription do
  @moduledoc """
  Polls a primary's catalog zone (RFC 9432) on its SOA refresh
  interval, AXFRs on serial change, and reconciles the member
  list via `ExDns.Zone.Catalog.Applier`.

  ## Lifecycle

  Each subscription is a single GenServer keyed on the catalog
  apex. State:

  ```
  %{
    catalog_apex: binary,
    primaries: [{ip, port}],
    tsig_key: binary | nil,
    poll_interval_ms: integer,
    member_defaults: keyword,
    last_serial: integer | nil,
    last_success_unix: integer | nil
  }
  ```

  On `init/1`, schedules an immediate poll. On every poll:

  1. Fetch the SOA of `catalog_apex` from each primary in turn.
  2. If the returned serial matches `last_serial`, do nothing
     and reschedule.
  3. Otherwise, AXFR the catalog, parse it via
     `ExDns.Zone.Catalog.parse/2`, and call
     `ExDns.Zone.Catalog.Applier.apply/2` with `member_defaults`.

  ## Configuration

      config :ex_dns, :catalogs, [
        %{
          catalog_apex: "catalog.example",
          primaries: [{{10, 0, 0, 1}, 53}],
          tsig_key: nil,
          poll_interval_seconds: 60,
          member_defaults: [
            primaries: [{{10, 0, 0, 1}, 53}],
            tsig_key: nil
          ]
        }
      ]

  ## Telemetry

  * `[:ex_dns, :catalog, :poll, :start]` — `%{catalog_apex}`.
  * `[:ex_dns, :catalog, :poll, :stop]` — measurements
    `%{duration, members}`, metadata `%{catalog_apex,
    serial_changed?, decision}` where `:decision` is `:applied`
    on serial change, `:up_to_date` otherwise, `:soa_failed`
    or `:axfr_failed` on errors.
  """

  use GenServer

  alias ExDns.Resource.SOA
  alias ExDns.Zone.Catalog
  alias ExDns.Zone.Catalog.Applier
  alias ExDns.Zone.Secondary.Client

  require Logger

  @default_poll_seconds 60

  @doc """
  Start a subscription for `catalog_apex`. Required keys:

  * `:catalog_apex`
  * `:primaries`

  Optional keys map to `Catalog.Applier.apply/2` defaults +
  poll interval.
  """
  @spec start_link(keyword()) :: GenServer.on_start()
  def start_link(options) when is_list(options) do
    apex = Keyword.fetch!(options, :catalog_apex)
    GenServer.start_link(__MODULE__, options, name: server_name(apex))
  end

  @doc "Trigger an immediate poll, bypassing the schedule. Returns `:ok`."
  @spec poll_now(binary()) :: :ok | {:error, :not_running}
  def poll_now(catalog_apex) when is_binary(catalog_apex) do
    case GenServer.whereis(server_name(catalog_apex)) do
      nil -> {:error, :not_running}
      pid -> GenServer.cast(pid, :poll_now)
    end
  end

  @doc "Snapshot of the subscription's state. Used by tests + admin tools."
  @spec snapshot(binary()) :: map() | nil
  def snapshot(catalog_apex) when is_binary(catalog_apex) do
    case GenServer.whereis(server_name(catalog_apex)) do
      nil -> nil
      pid -> GenServer.call(pid, :snapshot)
    end
  end

  @doc """
  Builds a Supervisor child spec from the operator's catalog
  configuration entry. `entry` is a single map with the same
  keys accepted by `start_link/1`.
  """
  @spec child_spec(map()) :: Supervisor.child_spec()
  def child_spec(%{catalog_apex: apex} = entry) do
    %{
      id: {__MODULE__, apex},
      start: {__MODULE__, :start_link, [Map.to_list(entry)]},
      type: :worker,
      restart: :permanent
    }
  end

  defp server_name(apex), do: {:global, {__MODULE__, normalize(apex)}}

  defp normalize(name) when is_atom(name), do: name |> Atom.to_string() |> normalize()
  defp normalize(name) when is_binary(name) do
    name |> String.trim_trailing(".") |> String.downcase(:ascii)
  end

  # ----- GenServer callbacks ---------------------------------------

  @impl true
  def init(options) do
    state = %{
      catalog_apex: Keyword.fetch!(options, :catalog_apex),
      primaries: Keyword.fetch!(options, :primaries),
      tsig_key: Keyword.get(options, :tsig_key),
      poll_interval_ms:
        Keyword.get(options, :poll_interval_seconds, @default_poll_seconds) * 1_000,
      member_defaults: Keyword.get(options, :member_defaults, []),
      last_serial: nil,
      last_success_unix: nil,
      client: Keyword.get(options, :client_module, Client)
    }

    schedule_poll(0)
    {:ok, state}
  end

  @impl true
  def handle_info(:poll, state) do
    new_state = do_poll(state)
    schedule_poll(state.poll_interval_ms)
    {:noreply, new_state}
  end

  @impl true
  def handle_cast(:poll_now, state) do
    {:noreply, do_poll(state)}
  end

  @impl true
  def handle_call(:snapshot, _from, state) do
    {:reply, snapshot_data(state), state}
  end

  defp schedule_poll(delay_ms) do
    Process.send_after(self(), :poll, delay_ms)
  end

  defp snapshot_data(state) do
    Map.take(state, [
      :catalog_apex,
      :primaries,
      :tsig_key,
      :poll_interval_ms,
      :last_serial,
      :last_success_unix
    ])
  end

  # ----- polling ----------------------------------------------------

  defp do_poll(state) do
    started_at = System.monotonic_time()

    :telemetry.execute(
      [:ex_dns, :catalog, :poll, :start],
      %{count: 1},
      %{catalog_apex: state.catalog_apex}
    )

    {decision, members_count, new_state} = poll_step(state)

    :telemetry.execute(
      [:ex_dns, :catalog, :poll, :stop],
      %{
        duration: System.monotonic_time() - started_at,
        members: members_count
      },
      %{
        catalog_apex: state.catalog_apex,
        decision: decision,
        serial_changed?: decision == :applied
      }
    )

    new_state
  end

  defp poll_step(state) do
    case fetch_soa(state) do
      {:ok, %SOA{serial: serial}} when serial == state.last_serial ->
        {:up_to_date, 0, %{state | last_success_unix: System.os_time(:second)}}

      {:ok, %SOA{serial: serial}} ->
        case fetch_axfr(state) do
          {:ok, records} ->
            apply_members(state.catalog_apex, records, state.member_defaults)

            {:applied, count_members(records, state.catalog_apex),
             %{state | last_serial: serial, last_success_unix: System.os_time(:second)}}

          {:error, reason} ->
            Logger.warning(
              "ExDns.Zone.Catalog.Subscription[#{state.catalog_apex}]: AXFR failed: #{inspect(reason)}"
            )

            {:axfr_failed, 0, state}
        end

      {:error, reason} ->
        Logger.warning(
          "ExDns.Zone.Catalog.Subscription[#{state.catalog_apex}]: SOA fetch failed: #{inspect(reason)}"
        )

        {:soa_failed, 0, state}
    end
  end

  defp apply_members(catalog_apex, records, member_defaults) do
    %{members: members} = Catalog.parse(catalog_apex, records)
    Applier.apply(members, member_defaults)
  end

  defp count_members(records, catalog_apex) do
    %{members: members} = Catalog.parse(catalog_apex, records)
    length(members)
  end

  defp fetch_soa(%{primaries: primaries} = state) do
    Enum.reduce_while(primaries, {:error, :no_primaries}, fn primary, _ ->
      case state.client.fetch_soa(state.catalog_apex, primary, client_options(state.tsig_key)) do
        {:ok, _} = ok -> {:halt, ok}
        {:error, _} = err -> {:cont, err}
      end
    end)
  end

  defp fetch_axfr(%{primaries: primaries} = state) do
    Enum.reduce_while(primaries, {:error, :no_primaries}, fn primary, _ ->
      case state.client.fetch_axfr(state.catalog_apex, primary, client_options(state.tsig_key)) do
        {:ok, _} = ok -> {:halt, ok}
        {:error, _} = err -> {:cont, err}
      end
    end)
  end

  defp client_options(nil), do: []
  defp client_options(key) when is_binary(key), do: [tsig_key: key]
end
