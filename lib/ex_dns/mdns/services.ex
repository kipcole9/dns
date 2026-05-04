defmodule ExDns.MDNS.Services do
  @moduledoc """
  DNS-SD (RFC 6763) service registry on top of the mDNS responder.

  Lets the application register services that mDNS clients
  (`dns-sd -B`, Bonjour, Avahi) can discover. For each registered
  service the registry synthesises and publishes:

  * a PTR record at `_<service>._<proto>.local` pointing at
    `<instance>._<service>._<proto>.local` (one per instance);
  * an SRV record at the instance name with priority, weight, port,
    and target host;
  * a TXT record at the instance name carrying the supplied
    key=value strings;
  * a PTR record at `_services._dns-sd._udp.local` pointing at
    `_<service>._<proto>.local` so the meta-service browser sees the
    service type;
  * an A (or AAAA) record at the target host if the caller supplied
    `:address`.

  The registry owns the `local` zone in `ExDns.Storage`. Any records
  inserted directly via `Storage.put_zone("local", …)` after a
  registration call will be **clobbered** on the next register /
  unregister — keep the registry as the single writer for `.local`,
  or register all services before pushing other records.

  ## Example

      ExDns.MDNS.Services.register(
        instance: "MyPrinter",
        service: "_http._tcp",
        port: 80,
        target: "myprinter.local",
        address: {192, 168, 1, 50},
        txt: ["path=/admin", "color=true"]
      )

  After that, `dns-sd -B _http._tcp` (or any DNS-SD client) sees the
  service.

  """

  use GenServer

  alias ExDns.Resource.{A, AAAA, PTR, SRV, TXT}
  alias ExDns.Storage

  @apex "local"
  @meta_browser "_services._dns-sd._udp.local"

  # ----- public API ---------------------------------------------------

  @doc false
  def child_spec(_options) do
    %{
      id: __MODULE__,
      start: {__MODULE__, :start_link, [[]]},
      type: :worker,
      restart: :permanent,
      shutdown: 5_000
    }
  end

  def start_link(_opts) do
    GenServer.start_link(__MODULE__, %{}, name: __MODULE__)
  end

  @doc """
  Registers a service.

  ### Options

  * `:instance` — the instance name (e.g. `"MyPrinter"`). Required.
  * `:service` — the service-type pair `"_http._tcp"`. Required.
  * `:port` — the listening port. Required.
  * `:target` — the host the SRV record points at. Defaults to
    `"<instance>.local"` with non-DNS characters stripped.
  * `:address` — `{a, b, c, d}` or `{a, b, c, d, e, f, g, h}`. When
    set, an A or AAAA record at `:target` is also published.
  * `:txt` — list of `"key=value"` strings (default `[""]`, the
    empty single-string TXT that DNS-SD requires).
  * `:priority`, `:weight` — SRV fields, defaults `0`.
  * `:ttl` — record TTL, default 120 (per RFC 6762 §10).

  """
  @spec register(keyword()) :: :ok
  def register(options) do
    GenServer.call(__MODULE__, {:register, normalize(options)})
  end

  @doc "Removes a service. Idempotent."
  @spec unregister(instance :: binary(), service :: binary()) :: :ok
  def unregister(instance, service) do
    GenServer.call(__MODULE__, {:unregister, instance, service})
  end

  @doc "Returns the list of currently-registered services."
  @spec list() :: [map()]
  def list do
    GenServer.call(__MODULE__, :list)
  end

  @doc "Drops every registration. Mainly for tests."
  @spec clear() :: :ok
  def clear do
    GenServer.call(__MODULE__, :clear)
  end

  # ----- GenServer ----------------------------------------------------

  @impl true
  def init(_state) do
    {:ok, %{services: %{}, last_published: []}}
  end

  @impl true
  def handle_call({:register, service}, _from, state) do
    key = {service.instance, service.service}
    services = Map.put(state.services, key, service)
    last_published = publish(services, state.last_published)
    {:reply, :ok, %{state | services: services, last_published: last_published}}
  end

  def handle_call({:unregister, instance, service}, _from, state) do
    services = Map.delete(state.services, {instance, service})
    last_published = publish(services, state.last_published)
    {:reply, :ok, %{state | services: services, last_published: last_published}}
  end

  def handle_call(:list, _from, state) do
    {:reply, Map.values(state.services), state}
  end

  def handle_call(:clear, _from, state) do
    last_published = publish(%{}, state.last_published)
    {:reply, :ok, %{state | services: %{}, last_published: last_published}}
  end

  # ----- record synthesis --------------------------------------------

  # Computes the synthesised set, then merges with any non-service
  # records already in the local zone — preserving them so that user
  # data put with `Storage.put_zone("local", …)` survives a service
  # registration. We achieve this by:
  #
  # 1. Loading the current zone.
  # 2. Removing the records WE last published (so we don't accumulate
  #    stale entries between calls).
  # 3. Appending the new synthesised set.
  # 4. Writing the union back.
  #
  # Returns the freshly synthesised set so the caller can remember it
  # for the next round of bookkeeping.
  defp publish(services, last_published) do
    new_records =
      services
      |> Map.values()
      |> Enum.flat_map(&records_for/1)
      |> Enum.uniq()

    existing =
      case Storage.dump_zone(@apex) do
        {:ok, records} -> records
        {:error, :not_loaded} -> []
      end

    preserved = existing -- last_published
    Storage.put_zone(@apex, preserved ++ new_records)
    new_records
  end

  defp records_for(service) do
    %{
      instance: instance,
      service: service_type,
      port: port,
      target: target,
      txt: txt_strings,
      priority: priority,
      weight: weight,
      ttl: ttl,
      address: address
    } = service

    instance_name = "#{instance}.#{service_type}.local"

    base = [
      # Instance PTR for the service type.
      %PTR{name: "#{service_type}.local", ttl: ttl, class: :in, pointer: instance_name},
      # SRV for the instance.
      %SRV{
        name: instance_name,
        ttl: ttl,
        class: :in,
        priority: priority,
        weight: weight,
        port: port,
        target: target
      },
      # TXT for the instance.
      %TXT{name: instance_name, ttl: ttl, class: :in, strings: txt_strings},
      # Meta service browser PTR.
      %PTR{
        name: @meta_browser,
        ttl: ttl,
        class: :in,
        pointer: "#{service_type}.local"
      }
    ]

    case address do
      {_, _, _, _} = ipv4 ->
        [%A{name: target, ttl: ttl, class: :in, ipv4: ipv4} | base]

      {_, _, _, _, _, _, _, _} = ipv6 ->
        [%AAAA{name: target, ttl: ttl, class: :in, ipv6: ipv6} | base]

      nil ->
        base
    end
  end

  # ----- option normalisation -----------------------------------------

  defp normalize(options) do
    instance = Keyword.fetch!(options, :instance)
    service = Keyword.fetch!(options, :service)
    port = Keyword.fetch!(options, :port)

    target =
      Keyword.get_lazy(options, :target, fn ->
        normalised = String.replace(instance, ~r/[^A-Za-z0-9-]/, "-")
        "#{normalised}.local"
      end)

    %{
      instance: instance,
      service: service,
      port: port,
      target: target,
      txt: Keyword.get(options, :txt, [""]),
      priority: Keyword.get(options, :priority, 0),
      weight: Keyword.get(options, :weight, 0),
      ttl: Keyword.get(options, :ttl, 120),
      address: Keyword.get(options, :address)
    }
  end
end
