defmodule ExDns.BlackHole.Plugin do
  @moduledoc """
  The BlackHole plugin module.

  ## Behaviours implemented

  * `ExDns.Plugin` — metadata + UI declaration.
  * `ExDns.Plugin.Policy` — `routes/0` (computed from the
    groups table) + `policy_resolve/2` (consults the
    compiled match set + allow / deny lists).
  * `ExDns.Plugin.Action` — mutating UI actions (add /
    remove / refresh entries; group editor; "disable for
    N seconds" affordance).

  ## Resources

  * `:overview` — totals + top-N counters.
  * `:blocklists` / `:allowlist` / `:denylist` / `:groups` —
    list configurations from storage.
  * `:query_log` — paginated bounded log.
  """

  @behaviour ExDns.Plugin
  @behaviour ExDns.Plugin.Policy
  @behaviour ExDns.Plugin.Action

  alias ExDns.BlackHole.{Groups, Set, Storage}
  alias ExDns.Plugin.Registry

  @impl ExDns.Plugin
  def metadata do
    %{
      slug: :black_hole,
      name: "BlackHole",
      version: "0.1.0",
      ui: %{
        title: "BlackHole",
        view: :table,
        resources: [:overview, :blocklists, :allowlist, :denylist, :groups, :query_log]
      }
    }
  end

  @impl ExDns.Plugin
  def get_resource(:overview), do: {:ok, overview()}
  def get_resource(:blocklists), do: {:ok, Storage.list_blocklists()}
  def get_resource(:allowlist), do: {:ok, Storage.list_allow()}
  def get_resource(:denylist), do: {:ok, Storage.list_deny()}
  def get_resource(:groups), do: {:ok, Storage.list_groups()}

  def get_resource(:query_log) do
    {:ok, Storage.read_query_log(%{limit: 100})}
  end

  def get_resource(_), do: {:error, :not_found}

  # ----- ExDns.Plugin.Policy ----------------------------------------

  @impl ExDns.Plugin.Policy
  def routes, do: Groups.routes()

  @impl ExDns.Plugin.Policy
  def policy_resolve(request, _route) do
    qname = qname_of(request)

    decision =
      cond do
        qname == "" -> :cont
        allowed?(qname) -> :allow
        denied?(qname) or in_blocklist?(qname) -> :block
        true -> :allow
      end

    log(request, qname, decision)
    do_decision(decision, request)
  end

  defp do_decision(:cont, _request), do: :cont
  defp do_decision(:allow, _request), do: :cont
  defp do_decision(:block, request), do: block(request)

  defp log(request, qname, decision) do
    ExDns.BlackHole.QueryLog.enqueue(%{
      "ts_ns" => System.os_time(:nanosecond),
      "client_ip" => format_ip(request.source_ip),
      "qname" => qname,
      "qtype" => qtype_of(request),
      "decision" => Atom.to_string(decision),
      "matched_list_id" => nil,
      "response_code" => decision_to_rc(decision),
      "latency_us" => 0
    })

    :telemetry.execute(
      [:ex_dns, :black_hole, decision_event(decision)],
      %{count: 1},
      %{qname: qname, qtype: qtype_of(request), source_ip: request.source_ip}
    )
  end

  defp decision_event(:block), do: :match
  defp decision_event(_), do: :allow

  defp decision_to_rc(:block) do
    case configured_block_response() do
      :nxdomain -> 3
      _ -> 0
    end
  end

  defp decision_to_rc(_), do: 0

  defp format_ip(nil), do: ""
  defp format_ip(ip), do: ip |> :inet.ntoa() |> to_string()

  defp qtype_of(%ExDns.Request{message: %{question: %{type: type}}}) when is_atom(type) do
    Atom.to_string(type)
  end

  defp qtype_of(_), do: ""

  # ----- helpers -----------------------------------------------------

  defp qname_of(%ExDns.Request{message: %{question: %{host: host}}}) when is_binary(host) do
    host |> String.trim_trailing(".") |> String.downcase(:ascii)
  end

  defp qname_of(_), do: ""

  defp allowed?(qname) do
    Storage.list_allow()
    |> Enum.any?(fn entry -> normalise(entry["domain"]) == qname end)
  rescue
    _ -> false
  end

  defp denied?(qname) do
    Storage.list_deny()
    |> Enum.any?(fn entry -> normalise(entry["domain"]) == qname end)
  rescue
    _ -> false
  end

  defp in_blocklist?(qname) do
    Set.match?(Set.current(), qname)
  end

  defp block(_request) do
    case configured_block_response() do
      :nxdomain -> {:halt, :nxdomain}
      :zero_ip -> {:halt, {:redirect, {0, 0, 0, 0}}}
      :refused -> {:halt, :nxdomain}
    end
  end

  defp configured_block_response do
    Application.get_env(:ex_dns, :black_hole, [])
    |> Keyword.get(:default_block_response, :nxdomain)
  end

  defp overview do
    blocklists = Storage.list_blocklists()
    %{rows: rows} = Storage.read_query_log(%{limit: 1000})

    {blocked, allowed} =
      Enum.reduce(rows, {0, 0}, fn row, {b, a} ->
        if row["decision"] == "block", do: {b + 1, a}, else: {b, a + 1}
      end)

    total = blocked + allowed

    %{
      "queries_today" => total,
      "blocked_today" => blocked,
      "percent_blocked" =>
        if(total == 0, do: 0.0, else: Float.round(blocked / total * 100, 2)),
      "active_blocklists" => Enum.count(blocklists, fn b -> b["enabled"] end),
      "top_queried" => top_n(rows, "qname", 5),
      "top_blocked" =>
        rows |> Enum.filter(fn r -> r["decision"] == "block" end) |> top_n("qname", 5),
      "top_clients" => top_n(rows, "client_ip", 5)
    }
  end

  defp top_n(rows, key, n) do
    rows
    |> Enum.frequencies_by(fn r -> Map.get(r, key) end)
    |> Enum.sort_by(fn {_k, v} -> -v end)
    |> Enum.take(n)
    |> Enum.map(fn {k, v} -> %{"key" => k, "count" => v} end)
  end

  defp normalise(nil), do: ""
  defp normalise(s) when is_binary(s), do: s |> String.trim_trailing(".") |> String.downcase(:ascii)

  # ----- ExDns.Plugin.Action ----------------------------------------

  @impl ExDns.Plugin.Action
  def handle_action("add_blocklist", %{"url" => url} = params) do
    Storage.put_blocklist(%{
      "url" => url,
      "name" => Map.get(params, "name", url),
      "enabled" => Map.get(params, "enabled", true)
    })
  end

  def handle_action("remove_blocklist", %{"id" => id}) do
    :ok = Storage.delete_blocklist(id)
    {:ok, %{"id" => id}}
  end

  def handle_action("set_blocklist_enabled", %{"id" => id, "enabled" => enabled}) do
    case Storage.list_blocklists() |> Enum.find(fn r -> r["id"] == id end) do
      nil -> {:error, :unknown_blocklist}
      row -> Storage.put_blocklist(Map.put(row, "enabled", enabled))
    end
  end

  def handle_action("add_allowlist", %{"domain" => domain} = params) do
    Storage.put_allow(%{
      "domain" => normalise(domain),
      "added_at" => System.os_time(:second),
      "added_by" => Map.get(params, "added_by"),
      "comment" => Map.get(params, "comment")
    })
  end

  def handle_action("remove_allowlist", %{"domain" => domain}) do
    :ok = Storage.delete_allow(normalise(domain))
    {:ok, %{"domain" => domain}}
  end

  def handle_action("add_denylist", %{"domain" => domain} = params) do
    {:ok, _} =
      Storage.put_deny(%{
        "domain" => normalise(domain),
        "added_at" => System.os_time(:second),
        "added_by" => Map.get(params, "added_by"),
        "comment" => Map.get(params, "comment")
      })

    {:ok, %{"domain" => normalise(domain)}}
  end

  def handle_action("remove_denylist", %{"domain" => domain}) do
    :ok = Storage.delete_deny(normalise(domain))
    {:ok, %{"domain" => domain}}
  end

  def handle_action("add_group", %{"name" => _} = params) do
    {:ok, group} =
      Storage.put_group(%{
        "name" => Map.fetch!(params, "name"),
        "enabled" => Map.get(params, "enabled", true),
        "cidrs" => Map.get(params, "cidrs", []),
        "blocklist_ids" => Map.get(params, "blocklist_ids", [])
      })

    refresh_routes()
    {:ok, group}
  end

  def handle_action("remove_group", %{"id" => id}) do
    :ok = Storage.delete_group(id)
    refresh_routes()
    {:ok, %{"id" => id}}
  end

  def handle_action("clear_query_log", _params) do
    :ok = Storage.truncate_query_log()
    {:ok, %{"truncated" => true}}
  end

  def handle_action(name, _params), do: {:error, {:unknown_action, name}}

  defp refresh_routes do
    Registry.update_routes(:black_hole, routes())
    :ok
  end
end
