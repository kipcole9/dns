defmodule ExDns.Application do
  @moduledoc false

  use Application

  @impl true
  def prep_stop(state) do
    # Run the drain BEFORE the supervisor starts shutting children
    # down. This flips the readiness probe to "not ready", closes
    # listener sockets so no more queries arrive, and waits for
    # in-flight workers to finish (bounded by the configured
    # timeout, default 30s).
    options = Application.get_env(:ex_dns, :drain, [])
    _ = ExDns.Drain.drain(options)
    state
  end

  @impl true
  def start(_type, _args) do
    # Clear any drain flag left by a previous instance of the
    # application in this BEAM (relevant in tests that stop and
    # restart the supervisor).
    ExDns.Drain.clear_draining()

    # If an `EXDNS_CONFIG` env var or `:config_file` Application
    # env points at an Elixir-data config file, load + apply it
    # before any subsystem reads its settings.
    ExDns.Config.load_if_configured()

    # The configured storage backend is initialised eagerly so that any
    # zones configured for autoload below can be inserted as the
    # supervision tree comes up.
    ExDns.Storage.init()

    port = ExDns.listener_port()

    children =
      [
        {ExDns.Listener.UDP, listener_options(:inet)},
        Supervisor.child_spec({ExDns.Listener.UDP, listener_options(:inet6)},
          id: ExDns.Listener.UDP6
        ),
        {ExDns.Listener.TCP,
         port: port, transport_options: [ip: {127, 0, 0, 1}, reuseaddr: true]},
        ExDns.Resolver.Supervisor
      ] ++
        doh_children() ++
        dot_children() ++
        mdns_children() ++
        cluster_children() ++
        metrics_children() ++
        dnstap_children() ++
        health_children() ++
        admin_children() ++
        secondary_zone_children()

    opts = [strategy: :one_for_one, name: ExDns.Supervisor]

    case Supervisor.start_link(children, opts) do
      {:ok, _pid} = ok ->
        autoload_zones()
        attach_optional_telemetry_handlers()
        ExDns.SystemD.notify_ready()
        ok

      other ->
        other
    end
  end

  # Optional telemetry handlers wired in based on application config.
  # Each is opt-in so the production footprint stays at zero until an
  # operator turns the feature on.
  defp attach_optional_telemetry_handlers do
    case Application.get_env(:ex_dns, :structured_logs) do
      options when is_list(options) ->
        if Keyword.get(options, :enabled, false) do
          _ = ExDns.Telemetry.StructuredLogger.attach()
        end

      _ ->
        :ok
    end

    case Application.get_env(:ex_dns, :open_telemetry) do
      options when is_list(options) ->
        if Keyword.get(options, :enabled, false) do
          _ = ExDns.Telemetry.OpenTelemetry.attach()
        end

      _ ->
        :ok
    end

    # The dnstap sink is started under the supervisor; here we just
    # attach the handler that funnels events into it.
    case Application.get_env(:ex_dns, :dnstap) do
      options when is_list(options) ->
        if Keyword.get(options, :enabled, false) do
          case Process.whereis(ExDns.Telemetry.Dnstap.FileSink) do
            nil -> :ok
            sink -> _ = ExDns.Telemetry.Dnstap.attach(sink)
          end
        end

      _ ->
        :ok
    end
  end

  # Loads any zone files listed under `:zones` in application config.
  # Failures are logged but do not bring the supervisor down — a zone
  # with a syntax error should not prevent the server from starting.
  defp autoload_zones do
    require Logger

    Application.get_env(:ex_dns, :zones, [])
    |> ExDns.Zone.Source.expand()
    |> Enum.each(fn path ->
      case ExDns.Zone.load_file(path) do
        {:ok, zone} ->
          Logger.info("Loaded zone #{ExDns.Zone.name(zone)} from #{path}")

        {:error, reason} ->
          Logger.error("Failed to load zone #{path}: #{inspect(reason)}")
      end
    end)
  end

  def listener_options(inet_family, address \\ nil)

  def listener_options(inet_family, nil) do
    address =
      case inet_family do
        :inet -> "127.0.0.1"
        :inet6 -> "::1"
        _ -> raise ArgumentError, "Unknown inet_family: #{inspect(inet_family)}"
      end

    listener_options(inet_family, address)
  end

  def listener_options(inet_family, address) when is_binary(address) do
    {:ok, ip_address} =
      address
      |> String.to_charlist()
      |> :inet_parse.address()

    listener_options(inet_family, ip_address)
  end

  def listener_options(inet_family, address) do
    %{
      inet_family: inet_family,
      address: address,
      port: ExDns.listener_port(),
      socket_options: socket_options()
    }
  end

  # Returns a Bandit listener serving the operator admin API
  # (zone reload, secondary state inspection, etc.) when
  # `:ex_dns, :admin, [enabled: true, port: ...]` is configured.
  # Defaults to binding 127.0.0.1 — the API exposes operational
  # control and should not be reachable from arbitrary networks
  # without a TLS proxy.
  defp admin_children do
    case Application.get_env(:ex_dns, :admin) do
      nil ->
        []

      options when is_list(options) ->
        if Keyword.get(options, :enabled, false) do
          port = Keyword.get(options, :port, 9570)
          ip = Keyword.get(options, :bind, {127, 0, 0, 1})

          [
            Supervisor.child_spec(
              {Bandit,
               plug: ExDns.Admin,
               scheme: :http,
               port: port,
               thousand_island_options: [transport_options: [ip: ip]]},
              id: ExDns.Admin
            )
          ]
        else
          []
        end
    end
  end

  # Returns a Bandit listener serving the /healthz + /readyz probes
  # when `:ex_dns, :health, [enabled: true, port: ...]` is configured.
  # Off by default. Bound to all interfaces because orchestrators
  # typically probe from the host network namespace.
  defp health_children do
    case Application.get_env(:ex_dns, :health) do
      nil ->
        []

      options when is_list(options) ->
        if Keyword.get(options, :enabled, false) do
          port = Keyword.get(options, :port, 9569)

          [
            Supervisor.child_spec(
              {Bandit, plug: ExDns.Health, scheme: :http, port: port},
              id: ExDns.Health
            )
          ]
        else
          []
        end
    end
  end

  # Starts one `ExDns.Zone.Secondary` per entry in
  # `:ex_dns, :secondary_zones`, all under
  # `ExDns.Zone.Secondary.Supervisor`. When no zones are
  # configured the supervisor is omitted entirely so an empty
  # config has zero supervision-tree footprint.
  defp secondary_zone_children do
    case Application.get_env(:ex_dns, :secondary_zones, []) do
      [] -> []
      zones when is_list(zones) -> [ExDns.Zone.Secondary.Supervisor]
    end
  end

  # Returns the dnstap file-sink child spec when
  # `:ex_dns, :dnstap, [enabled: true, path: ...]` is configured. The
  # handler that pipes telemetry events into the sink is attached
  # by `attach_optional_telemetry_handlers/0` after the supervisor
  # comes up.
  defp dnstap_children do
    case Application.get_env(:ex_dns, :dnstap) do
      nil ->
        []

      options when is_list(options) ->
        if Keyword.get(options, :enabled, false) do
          path = Keyword.get(options, :path) || raise ":ex_dns, :dnstap requires :path"

          [
            Supervisor.child_spec(
              {ExDns.Telemetry.Dnstap.FileSink,
               path: path, name: ExDns.Telemetry.Dnstap.FileSink},
              id: ExDns.Telemetry.Dnstap.FileSink
            )
          ]
        else
          []
        end
    end
  end

  # Returns the Prometheus metrics exporter child spec when
  # `:ex_dns, :metrics, [enabled: true]` is configured. Off by default
  # so the production footprint stays at zero until an operator opts
  # in.
  defp metrics_children do
    case Application.get_env(:ex_dns, :metrics) do
      nil ->
        []

      options when is_list(options) ->
        if Keyword.get(options, :enabled, false) do
          [ExDns.Metrics.child_spec(options)]
        else
          []
        end
    end
  end

  # Returns the DoT (DNS-over-TLS, RFC 7858) child spec when
  # `:ex_dns, :dot, [enabled: true, certfile: ..., keyfile: ...]`
  # is configured. Off by default.
  defp dot_children do
    case Application.get_env(:ex_dns, :dot) do
      nil ->
        []

      options when is_list(options) ->
        if Keyword.get(options, :enabled, false) do
          [ExDns.Listener.DoT.child_spec(options)]
        else
          []
        end
    end
  end

  # Returns the DoH child spec when `:ex_dns, :doh` is configured.
  defp doh_children do
    case Application.get_env(:ex_dns, :doh) do
      nil -> []
      doh_options when is_list(doh_options) -> [{ExDns.Listener.DoH, doh_options}]
    end
  end

  # Returns the cluster child spec when clustering is enabled. Cluster
  # membership is opt-in (`:ex_dns, :cluster, true`) — the default
  # single-node deployment doesn't need it.
  defp cluster_children do
    if Application.get_env(:ex_dns, :cluster, false) do
      [{ExDns.Cluster, []}]
    else
      []
    end
  end

  # mDNS responder is opt-in (`:ex_dns, :mdns, [enabled: true]`) —
  # binds the multicast socket only when explicitly requested. The
  # DNS-SD service registry comes along for the ride so apps can
  # call `ExDns.MDNS.Services.register/1` once the supervision tree
  # is up.
  defp mdns_children do
    case Application.get_env(:ex_dns, :mdns) do
      nil ->
        []

      options when is_list(options) ->
        if Keyword.get(options, :enabled, false) do
          [
            ExDns.MDNS.Services,
            {ExDns.Listener.MDNS, options}
          ]
        else
          []
        end
    end
  end

  def socket_options do
    case :os.type() do
      {:unix, :linux} -> [{:raw, 1, 15, <<1::native-size(32)>>}]
      {:unix, :darwin} -> [{:raw, 0xFFFF, 0x0200, <<1::native-size(32)>>}]
      _ -> []
    end
  end
end
