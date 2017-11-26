defmodule ExDns.Application do
  use Application
  alias ExDns.Prometheus.Instrumenter

  def start(_type, _args) do
    import Supervisor.Spec, warn: false

    # Define our metrics
    Instrumenter.setup

    # Define workers and child supervisors to be supervised
    children = [
      worker(ExDns.Prometheus.Router, []),
      worker(ExDns.Listener.UDP, listener_options(:inet), id: ExDns.Listener.UDP4),
      worker(ExDns.Listener.UDP, listener_options(:inet6), id: ExDns.Listener.UDP6),
      supervisor(ExDns.Resolver.Supervisor, [])
    ]

    # See http://elixir-lang.org/docs/stable/elixir/Supervisor.html
    # for other strategies and supported options
    opts = [strategy: :one_for_one, name: ExDns.Supervisor]
    Supervisor.start_link(children, opts)
  end

  def listener_options(inet_family, address \\ nil)
  def listener_options(inet_family, nil) do
    address = case inet_family do
      :inet  -> "127.0.0.1"
      :inet6 -> "::1"
      _      -> raise ArgumentError, "Unknown inet_family: #{inspect inet_family}"
    end
    listener_options(inet_family, address)
  end

  def listener_options(inet_family, address) when is_binary(address) do
    {:ok, ip_address} = address
    |> String.to_charlist
    |> :inet_parse.address

    listener_options(inet_family, ip_address)
  end

  def listener_options(inet_family, address) do
    [
      %{inet_family: inet_family,
        address: address,
        port: ExDns.listener_port,
        socket_options: socket_options()}
    ]
  end

  def socket_options do
    case :os.type() do
      {:unix, :linux} -> [{:raw, 1, 15, <<1 :: native-size(32)>>}]
      {:unix, :darwin} -> [{:raw, 0xffff, 0x0200, <<1 :: native-size(32)>>}]
      _ -> []
    end
  end
end
