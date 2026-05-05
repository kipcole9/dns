defmodule ExDns.Plugin.Policy do
  @moduledoc """
  Behaviour for plugins that intercept DNS queries before the
  underlying resolver runs.

  ## How dispatch works

  A plugin opts into per-query interception by declaring its
  routes via `routes/0` and implementing `policy_resolve/2`.
  The plugin registry maintains a route index keyed on
  `{source_ip_cidr, qtype, qname_suffix}`. On each request the
  resolver does a single longest-prefix lookup against the
  index — at most one plugin matches, and *only* the matched
  plugin's `policy_resolve/2` runs. Queries that match no
  route flow straight through to the underlying resolver as
  if no plugins were installed.

  This routing primitive serves both filtering plugins
  (BlackHole-style: register CIDRs of clients to filter) and
  authoritative-side synthesis plugins (anycast-style:
  register CIDRs scoped to a `qname_suffix` for a specific
  zone).

  ## Tiebreaking

  When multiple routes claim the same query: longest CIDR
  prefix wins; ties broken by higher `priority`; final
  tiebreaker is registration order.

  ## Returns from `policy_resolve/2`

  * `:cont` — let the underlying resolver handle this query.
  * `{:halt, %ExDns.Message{}}` — fully-formed response; sent
    as-is.
  * `{:halt, :nxdomain}` — synthesise an authoritative
    NXDOMAIN for the request's qname.
  * `{:halt, {:redirect, ip}}` — synthesise an A/AAAA pointing
    at `ip`.
  """

  @type cidr :: {:inet.ip_address(), 0..128}

  @type route :: %{
          required(:cidrs) => [cidr()],
          optional(:qtypes) => [atom()] | :any,
          optional(:qname_suffix) => binary() | nil,
          optional(:priority) => integer()
        }

  @callback routes() :: [route()]

  @callback policy_resolve(ExDns.Request.t(), matched_route :: route()) ::
              :cont
              | {:halt, ExDns.Message.t()}
              | {:halt, :nxdomain}
              | {:halt, {:redirect, :inet.ip_address()}}

  @optional_callbacks routes: 0
end
