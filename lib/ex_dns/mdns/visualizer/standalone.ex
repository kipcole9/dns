defmodule ExDns.MDNS.Visualizer.Standalone do
  @moduledoc """
  One-call wrapper that boots both the discoverer and the HTTP
  visualizer.

  Use from an `iex -S mix` session:

      iex> ExDns.MDNS.Visualizer.Standalone.start(port: 4001)
      {:ok, [discoverer_pid, bandit_pid]}

  Then visit http://localhost:4001 in a browser. The page lists
  every mDNS service the discoverer has observed, refreshing every
  5 seconds.

  ## Options

  * `:port` — HTTP port (default 4001).
  * `:interval` — discoverer refresh interval in ms (default 5_000).
  * `:listen_window` — how long to wait for replies per cycle in ms
    (default 1_000).
  * `:multicast_ip` — destination IP for browse queries
    (default `{224, 0, 0, 251}`).
  * `:mdns_port` — destination port for browse queries (default 5353).

  """

  alias ExDns.MDNS.Visualizer
  alias ExDns.MDNS.Visualizer.Discoverer

  @doc """
  Starts the discoverer (if not running) and a Bandit server hosting
  the `Visualizer` Plug router.

  Returns `{:ok, [discoverer_pid, http_pid]}` on success.
  """
  @spec start(keyword()) :: {:ok, [pid()]} | {:error, term()}
  def start(options \\ []) do
    port = Keyword.get(options, :port, 4001)

    discoverer_options =
      options
      |> Keyword.take([:interval, :listen_window, :multicast_ip])
      |> maybe_put_port(options)

    with {:ok, discoverer_pid} <- ensure_discoverer(discoverer_options),
         {:ok, http_pid} <- start_http(port) do
      {:ok, [discoverer_pid, http_pid]}
    end
  end

  defp maybe_put_port(discoverer_options, options) do
    case Keyword.fetch(options, :mdns_port) do
      {:ok, port} -> Keyword.put(discoverer_options, :port, port)
      :error -> discoverer_options
    end
  end

  defp ensure_discoverer(options) do
    case Process.whereis(Discoverer) do
      nil -> Discoverer.start_link(options)
      pid -> {:ok, pid}
    end
  end

  defp start_http(port) do
    Bandit.start_link(plug: Visualizer, scheme: :http, port: port)
  end

  @doc "Stops the discoverer and any standalone HTTP server."
  @spec stop() :: :ok
  def stop do
    case Process.whereis(Discoverer) do
      nil -> :ok
      pid -> GenServer.stop(pid)
    end
  end
end
