defmodule ExDns.BlackHole.Bootstrap do
  @moduledoc """
  One-call helper that flips ExDns into a working ad-blocker
  for a LAN. Used by the first-run setup wizard
  (`DnsUiWeb.SetupLive`) when the operator picks "Block ads
  on my LAN".

  ## What `enable_for_lan/1` does

  1. Detects the host's LAN CIDR(s) (skipping loopback,
     point-to-point, and link-local).

  2. Subscribes to a curated default blocklist (Steven Black
     unified hosts unless overridden).

  3. Creates a BlackHole group covering the detected CIDRs
     and bound to the blocklist.

  4. Triggers an immediate fetch so the operator sees
     blocking on the next query without waiting for the
     scheduled refresh interval.

  ## Re-entrancy

  Callable more than once. Detects an existing
  `"first-run"`-labelled blocklist + group and updates them
  in place rather than creating duplicates. Operators who
  ran the wizard once and want to re-detect the LAN can just
  call this again.
  """

  alias ExDns.BlackHole.Lists.Subscriber
  alias ExDns.BlackHole.Storage

  @default_blocklist_id "first-run"
  @default_blocklist_name "Steven Black unified hosts (first-run)"
  @default_blocklist_url "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"
  @default_group_id "first-run-lan"
  @default_group_name "LAN (first-run)"

  @doc """
  Enable LAN-scoped ad-blocking. Idempotent.

  ### Options

  * `:lan_cidrs` — list of CIDR strings to apply blocking
    to. Default: detected via `detect_lan_cidrs/0`.

  * `:blocklist_url` — adlist URL. Default: the Steven
    Black unified hosts.

  ### Returns

  * `{:ok, %{cidrs: cidrs, blocklist_id: id, group_id: id}}`
    — the configured CIDRs + the IDs of the rows we
    upserted.

  * `{:error, :no_lan_detected}` — `detect_lan_cidrs/0`
    returned an empty list and no `:lan_cidrs` was passed.

  ### Examples

      iex> {:ok, %{cidrs: cs}} = ExDns.BlackHole.Bootstrap.enable_for_lan(
      ...>   lan_cidrs: ["192.168.1.0/24"]
      ...> )
      iex> "192.168.1.0/24" in cs
      true

  """
  @spec enable_for_lan(keyword()) ::
          {:ok, %{cidrs: [binary()], blocklist_id: binary(), group_id: binary()}}
          | {:error, :no_lan_detected}
  def enable_for_lan(options \\ []) do
    cidrs =
      Keyword.get_lazy(options, :lan_cidrs, &detect_lan_cidrs/0)

    case cidrs do
      [] ->
        {:error, :no_lan_detected}

      cidrs ->
        url = Keyword.get(options, :blocklist_url, @default_blocklist_url)

        {:ok, blocklist} = upsert_blocklist(url)
        {:ok, group} = upsert_group(cidrs, blocklist["id"])

        # Best-effort fetch — failures are logged by the
        # subscriber and don't roll back the configuration.
        _ = Subscriber.refresh_now(blocklist["id"])

        {:ok,
         %{
           cidrs: cidrs,
           blocklist_id: blocklist["id"],
           group_id: group["id"]
         }}
    end
  end

  @doc """
  Detect the host's LAN CIDR(s). Skips loopback (`127.x`,
  `::1`), point-to-point, and IPv6 link-local
  (`fe80::/10`).

  ### Returns

  * A list of CIDR strings, e.g. `["192.168.1.0/24"]`. May
    be empty on a host with no useful interfaces.

  """
  @spec detect_lan_cidrs() :: [binary()]
  def detect_lan_cidrs do
    case :inet.getifaddrs() do
      {:ok, ifaces} ->
        ifaces
        |> Enum.flat_map(&cidrs_for_iface/1)
        |> Enum.uniq()

      _ ->
        []
    end
  end

  defp cidrs_for_iface({_name, opts}) do
    flags = Keyword.get(opts, :flags, [])

    cond do
      :loopback in flags -> []
      :pointtopoint in flags -> []
      :up not in flags -> []
      true -> extract_cidrs(opts)
    end
  end

  defp extract_cidrs(opts) do
    addrs = Keyword.get_values(opts, :addr)
    masks = Keyword.get_values(opts, :netmask)

    Enum.zip(addrs, masks)
    |> Enum.flat_map(fn pair ->
      case pair do
        {addr, mask} when tuple_size(addr) == 4 -> [v4_cidr(addr, mask)]
        # Skip link-local IPv6 — fe80::/10 — and most
        # other IPv6 cases for now. Operators with
        # IPv6-only LANs override via :lan_cidrs.
        _ -> []
      end
    end)
  end

  defp v4_cidr({a, b, c, d}, {ma, mb, mc, md}) do
    prefix_bits = popcount(ma) + popcount(mb) + popcount(mc) + popcount(md)

    network_a = Bitwise.band(a, ma)
    network_b = Bitwise.band(b, mb)
    network_c = Bitwise.band(c, mc)
    network_d = Bitwise.band(d, md)

    "#{network_a}.#{network_b}.#{network_c}.#{network_d}/#{prefix_bits}"
  end

  defp popcount(byte) when is_integer(byte) and byte >= 0 and byte <= 255 do
    Enum.sum(Enum.map(0..7, fn n -> Bitwise.band(Bitwise.bsr(byte, n), 1) end))
  end

  defp upsert_blocklist(url) do
    Storage.put_blocklist(%{
      "id" => @default_blocklist_id,
      "url" => url,
      "name" => @default_blocklist_name,
      "enabled" => true
    })
  end

  defp upsert_group(cidrs, blocklist_id) do
    Storage.put_group(%{
      "id" => @default_group_id,
      "name" => @default_group_name,
      "enabled" => true,
      "cidrs" => cidrs,
      "blocklist_ids" => [blocklist_id]
    })
  end
end
