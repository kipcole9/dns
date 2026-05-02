defmodule ExDns.Recursor.RootHints do
  @moduledoc """
  Hard-coded list of the 13 DNS root servers, with their IPv4 and IPv6
  addresses.

  These are used to seed iterative resolution when no closer
  delegation is cached. The list is current as of the IANA root hints
  file (named.root) for early 2026; it is stable enough to embed
  directly rather than fetching at boot, but operators with strong
  feelings about freshness can override the entire set via
  `Application.put_env(:ex_dns, :root_hints, ...)`.

  """

  @hints [
    {"a.root-servers.net", {198, 41, 0, 4},
     {0x2001, 0x0503, 0xBA3E, 0, 0, 0, 0x0002, 0x0030}},
    {"b.root-servers.net", {170, 247, 170, 2},
     {0x2801, 0x01B8, 0x0010, 0, 0, 0, 0, 0x000B}},
    {"c.root-servers.net", {192, 33, 4, 12}, {0x2001, 0x0500, 0x0002, 0, 0, 0, 0, 0x000C}},
    {"d.root-servers.net", {199, 7, 91, 13}, {0x2001, 0x0500, 0x002D, 0, 0, 0, 0, 0x000D}},
    {"e.root-servers.net", {192, 203, 230, 10},
     {0x2001, 0x0500, 0x00A8, 0, 0, 0, 0, 0x000E}},
    {"f.root-servers.net", {192, 5, 5, 241}, {0x2001, 0x0500, 0x002F, 0, 0, 0, 0, 0x000F}},
    {"g.root-servers.net", {192, 112, 36, 4},
     {0x2001, 0x0500, 0x0012, 0, 0, 0, 0, 0x0D0D}},
    {"h.root-servers.net", {198, 97, 190, 53},
     {0x2001, 0x0500, 0x0001, 0, 0, 0, 0, 0x0053}},
    {"i.root-servers.net", {192, 36, 148, 17}, {0x2001, 0x07FE, 0, 0, 0, 0, 0, 0x0053}},
    {"j.root-servers.net", {192, 58, 128, 30},
     {0x2001, 0x0503, 0x0C27, 0, 0, 0, 0x0002, 0x0030}},
    {"k.root-servers.net", {193, 0, 14, 129}, {0x2001, 0x07FD, 0, 0, 0, 0, 0, 0x0001}},
    {"l.root-servers.net", {199, 7, 83, 42}, {0x2001, 0x0500, 0x009F, 0, 0, 0, 0, 0x0042}},
    {"m.root-servers.net", {202, 12, 27, 33}, {0x2001, 0x0DC3, 0, 0, 0, 0, 0, 0x0035}}
  ]

  @doc """
  Returns the list of root hints as `{name, ipv4, ipv6}` tuples.

  Allows runtime override via `Application.get_env(:ex_dns, :root_hints)`.

  """
  @spec hints() :: [{binary(), :inet.ip4_address(), :inet.ip6_address()}]
  def hints do
    Application.get_env(:ex_dns, :root_hints, @hints)
  end

  @doc """
  Returns the list of root-server IPv4 addresses to query.
  """
  @spec ipv4_addresses() :: [:inet.ip4_address()]
  def ipv4_addresses do
    Enum.map(hints(), fn {_name, ipv4, _ipv6} -> ipv4 end)
  end

  @doc """
  Returns the list of root-server IPv6 addresses to query.
  """
  @spec ipv6_addresses() :: [:inet.ip6_address()]
  def ipv6_addresses do
    Enum.map(hints(), fn {_name, _ipv4, ipv6} -> ipv6 end)
  end

  @doc """
  Returns the synthetic NS RRset and matching glue (A + AAAA) for the
  root, ready to seed the cache.
  """
  @spec as_records() :: [struct()]
  def as_records do
    ns_records =
      Enum.map(hints(), fn {name, _ipv4, _ipv6} ->
        %ExDns.Resource.NS{name: "", ttl: 3_600_000, class: :in, server: name}
      end)

    a_records =
      Enum.map(hints(), fn {name, ipv4, _ipv6} ->
        %ExDns.Resource.A{name: name, ttl: 3_600_000, class: :in, ipv4: ipv4}
      end)

    aaaa_records =
      Enum.map(hints(), fn {name, _ipv4, ipv6} ->
        %ExDns.Resource.AAAA{name: name, ttl: 3_600_000, class: :in, ipv6: ipv6}
      end)

    ns_records ++ a_records ++ aaaa_records
  end
end
