defmodule ExDns.Application do
  @moduledoc false

  use Application

  @impl true
  def start(_type, _args) do
    # ETS-backed zone storage is initialised eagerly so that any zones
    # configured for autoload below can be inserted as the supervision
    # tree comes up.
    ExDns.Storage.ETS.init()

    children = [
      {ExDns.Listener.UDP, listener_options(:inet)},
      Supervisor.child_spec({ExDns.Listener.UDP, listener_options(:inet6)}, id: ExDns.Listener.UDP6),
      ExDns.Resolver.Supervisor
    ]

    opts = [strategy: :one_for_one, name: ExDns.Supervisor]

    case Supervisor.start_link(children, opts) do
      {:ok, _pid} = ok ->
        autoload_zones()
        ok

      other ->
        other
    end
  end

  # Loads any zone files listed under `:zones` in application config.
  # Failures are logged but do not bring the supervisor down — a zone
  # with a syntax error should not prevent the server from starting.
  defp autoload_zones do
    require Logger

    case Application.get_env(:ex_dns, :zones, []) do
      [] ->
        :ok

      zones when is_list(zones) ->
        Enum.each(zones, fn path ->
          case ExDns.Zone.load_file(path) do
            {:ok, zone} ->
              Logger.info("Loaded zone #{ExDns.Zone.name(zone)} from #{path}")

            {:error, reason} ->
              Logger.error("Failed to load zone #{path}: #{inspect(reason)}")
          end
        end)
    end
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

  def socket_options do
    case :os.type() do
      {:unix, :linux} -> [{:raw, 1, 15, <<1::native-size(32)>>}]
      {:unix, :darwin} -> [{:raw, 0xFFFF, 0x0200, <<1::native-size(32)>>}]
      _ -> []
    end
  end
end
