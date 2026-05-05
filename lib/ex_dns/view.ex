defmodule ExDns.View do
  @moduledoc """
  Per-client server views (BIND `view` clauses).

  A view is a named bundle of `{match_clauses, zone_set}`. When
  a query arrives, we walk the configured views in order and
  pick the first one whose match clauses fit the client. From
  then on, that query consults *only* that view's zone set — so
  the same apex (`example.com`) can resolve to different records
  for an internal client vs an external one ("split horizon"),
  for a TSIG-authenticated peer vs an anonymous one, and so on.

  ## Why this is a BIND-parity blocker

  Many production deployments use BIND views for:

  * **Split horizon DNS** — internal clients see RFC 1918
    addresses; external clients see public addresses. Same zone
    name, different data.
  * **Per-customer zone sets** — multi-tenant primaries serve
    customer A's zones to customer A's resolvers, customer B's
    zones to customer B's.
  * **Authenticated views** — TSIG-signed queries see admin
    records (debug zones, internal hostnames) that anonymous
    queries don't.

  Without views, BIND operators with any of these patterns
  cannot migrate.

  ## Match clauses

  Three matcher kinds, all combinable per-view:

  * `{:cidr, {ip, prefix}}` — match when the client IP is in the
    CIDR.

  * `{:tsig_key, name}` — match when the query was TSIG-signed
    by the named key.

  * `:any` — unconditional match. Always last in the chain;
    serves as the fallback view.

  A view matches when **any** of its clauses match (OR
  semantics within a view). Views are matched in the order
  they were registered.

  ## Configuration

      config :ex_dns, :views, [
        %{
          name: "internal",
          match: [{:cidr, {{10, 0, 0, 0}, 8}}, {:tsig_key, "internal-key"}],
          zones: ["internal/example.com"]
        },
        %{
          name: "external",
          match: [:any],
          zones: ["external/example.com"]
        }
      ]

  Each view's `zones` is a list of zone-source identifiers the
  storage backend understands (typically file paths or storage
  keys). The `Storage` backend is responsible for keeping each
  view's data isolated.

  ## Default view

  When no views are configured, all queries go to a single
  unnamed view that has access to every loaded zone. This
  preserves the pre-views behaviour exactly.
  """

  import Bitwise

  defstruct [:name, :match, :zones]

  @type matcher ::
          {:cidr, {:inet.ip_address(), 0..128}}
          | {:tsig_key, binary()}
          | :any

  @type t :: %__MODULE__{
          name: binary(),
          match: [matcher()],
          zones: [binary()]
        }

  @doc """
  Pick the first matching view for a client classification.

  ### Arguments

  * `client_ip` — the source-address tuple of the request.
  * `tsig_key_name` — `nil` when unsigned; binary key name when
    TSIG-verified.

  ### Returns

  * `%View{}` for the first matching configured view.
  * `nil` when no view matches AND no `:any` fallback is
    configured. In that state the resolver returns REFUSED.

  ### Examples

      iex> Application.delete_env(:ex_dns, :views)
      iex> ExDns.View.select({127, 0, 0, 1}, nil)
      nil

  """
  @spec select(:inet.ip_address(), binary() | nil) :: t() | nil
  def select(client_ip, tsig_key_name) do
    Enum.find(load_views(), fn view ->
      view_matches?(view, client_ip, tsig_key_name)
    end)
  end

  @doc """
  Return every configured view in order. Used by the admin UI
  + the introspection endpoints.
  """
  @spec list() :: [t()]
  def list, do: load_views()

  @doc """
  Test whether a single view's match clauses cover this client.
  Public so policies (or tests) can introspect.
  """
  @spec view_matches?(t(), :inet.ip_address(), binary() | nil) :: boolean()
  def view_matches?(%__MODULE__{match: clauses}, client_ip, tsig_key_name)
      when is_list(clauses) do
    Enum.any?(clauses, &clause_matches?(&1, client_ip, tsig_key_name))
  end

  defp clause_matches?(:any, _ip, _key), do: true
  defp clause_matches?({:tsig_key, name}, _ip, key), do: name == key
  defp clause_matches?({:cidr, cidr}, ip, _key), do: ip_in_cidr?(ip, cidr)
  defp clause_matches?(_, _, _), do: false

  defp load_views do
    Application.get_env(:ex_dns, :views, [])
    |> Enum.map(&normalise/1)
  end

  defp normalise(%__MODULE__{} = view), do: view

  defp normalise(map) when is_map(map) do
    %__MODULE__{
      name: Map.fetch!(map, :name),
      match: Map.get(map, :match, []),
      zones: Map.get(map, :zones, [])
    }
  end

  # ----- CIDR matching (same algorithm as Notify.ACL/Transfer.ACL) -

  defp ip_in_cidr?({a, b, c, d}, {{ca, cb, cc, cd}, prefix})
       when prefix in 0..32 do
    addr_int = (a <<< 24) ||| (b <<< 16) ||| (c <<< 8) ||| d
    cidr_int = (ca <<< 24) ||| (cb <<< 16) ||| (cc <<< 8) ||| cd
    drop = 32 - prefix
    mask = bsl(0xFFFFFFFF >>> drop, drop) &&& 0xFFFFFFFF
    (addr_int &&& mask) == (cidr_int &&& mask)
  end

  defp ip_in_cidr?({a, b, c, d, e, f, g, h}, {{ca, cb, cc, cd, ce, cf, cg, ch}, prefix})
       when prefix in 0..128 do
    addr_bytes = <<a::16, b::16, c::16, d::16, e::16, f::16, g::16, h::16>>
    cidr_bytes = <<ca::16, cb::16, cc::16, cd::16, ce::16, cf::16, cg::16, ch::16>>
    full_bytes = div(prefix, 8)
    extra_bits = rem(prefix, 8)

    head_match? =
      :binary.part(addr_bytes, 0, full_bytes) == :binary.part(cidr_bytes, 0, full_bytes)

    extra_match? =
      if extra_bits == 0 do
        true
      else
        <<ab::8>> = :binary.part(addr_bytes, full_bytes, 1)
        <<cb::8>> = :binary.part(cidr_bytes, full_bytes, 1)
        mask = bsl(0xFF >>> (8 - extra_bits), 8 - extra_bits) &&& 0xFF
        (ab &&& mask) == (cb &&& mask)
      end

    head_match? and extra_match?
  end

  defp ip_in_cidr?(_, _), do: false
end
