defmodule ExDns.MDNS.Visualizer.Render do
  @moduledoc """
  Pure-iodata HTML helpers for the mDNS visualizer.

  Mirrors the rendering layer of `Color.Palette.Visualizer.Render`:
  no template engine, no I/O, just string-building. Each function
  returns iodata so the caller can pass it straight to
  `Plug.Conn.send_resp/3`.
  """

  alias ExDns.MDNS.Visualizer.Assets

  @doc "Wraps `body` in the standard page chrome."
  @spec page(binary(), iodata(), iodata()) :: iodata()
  def page(title, body, refresh_meta \\ "") do
    [
      ~s(<!DOCTYPE html>\n),
      ~s(<html lang="en"><head>),
      ~s(<meta charset="utf-8">),
      ~s(<meta name="viewport" content="width=device-width, initial-scale=1">),
      refresh_meta,
      ~s(<title>),
      escape(title),
      ~s(</title>),
      ~s(<style>),
      Assets.css(),
      ~s(</style>),
      ~s(</head><body>),
      ~s(<header><h1>),
      escape(title),
      ~s(</h1></header>),
      ~s(<main>),
      body,
      ~s(</main>),
      ~s(<footer><p class="meta">),
      ~s(ExDns mDNS Visualizer ),
      ~s(&middot; auto-refreshes every 5&nbsp;s ),
      ~s(&middot; <a href="/refresh">refresh now</a>),
      ~s(</p></footer>),
      ~s(</body></html>)
    ]
  end

  @doc "Returns the meta-refresh header tag for the given seconds."
  @spec refresh(non_neg_integer()) :: iodata()
  def refresh(seconds) when is_integer(seconds) and seconds > 0 do
    [~s(<meta http-equiv="refresh" content="), Integer.to_string(seconds), ~s(">)]
  end

  @doc "Escapes a binary for safe insertion into HTML text/attributes."
  @spec escape(binary() | iodata() | nil) :: binary()
  def escape(nil), do: ""

  def escape(value) when is_binary(value) do
    value
    |> String.replace("&", "&amp;")
    |> String.replace("<", "&lt;")
    |> String.replace(">", "&gt;")
    |> String.replace(~s("), "&quot;")
    |> String.replace("'", "&#39;")
  end

  def escape(value) when is_integer(value), do: Integer.to_string(value)
  def escape(value) when is_list(value), do: value |> IO.iodata_to_binary() |> escape()

  @doc """
  Renders an `:inet.ip_address()` to its dotted/colon string form.
  """
  @spec format_ip(:inet.ip_address() | nil) :: binary()
  def format_ip(nil), do: ""

  def format_ip(address) when is_tuple(address) do
    case :inet.ntoa(address) do
      {:error, _} -> inspect(address)
      list -> List.to_string(list)
    end
  end

  @doc """
  Renders the discoverer snapshot as the visualizer's main view.
  """
  @spec snapshot_view(map()) :: iodata()
  def snapshot_view(snapshot) do
    [
      meta_panel(snapshot),
      services_panel(snapshot)
    ]
  end

  defp meta_panel(snapshot) do
    last =
      case snapshot.last_refresh do
        nil -> "—"
        dt -> dt |> DateTime.truncate(:second) |> DateTime.to_iso8601()
      end

    type_count = length(snapshot.types)

    instance_count =
      snapshot.services
      |> Map.values()
      |> Enum.map(&map_size/1)
      |> Enum.sum()

    [
      ~s(<section class="meta-panel">),
      ~s(<dl>),
      kv("Last refresh", escape(last)),
      kv("Cycles", escape(snapshot.cycles)),
      kv("Service types observed", escape(type_count)),
      kv("Instances observed", escape(instance_count)),
      ~s(</dl>),
      ~s(</section>)
    ]
  end

  defp kv(label, value) do
    [~s(<dt>), escape(label), ~s(</dt><dd>), value, ~s(</dd>)]
  end

  defp services_panel(snapshot) when map_size(snapshot.services) == 0 do
    [
      ~s(<section class="empty">),
      ~s(<p>No services discovered yet. Either no mDNS responders are advertising on this network, ),
      ~s(or we have not had time to receive their replies. Wait 5&nbsp;s for the next cycle, ),
      ~s(or click <a href="/refresh">refresh now</a>.</p>),
      ~s(</section>)
    ]
  end

  defp services_panel(snapshot) do
    [
      ~s(<section class="services">),
      Enum.map(Enum.sort(snapshot.services), fn {type, instances} ->
        type_panel(type, instances)
      end),
      ~s(</section>)
    ]
  end

  defp type_panel(type, instances) when map_size(instances) == 0 do
    [
      ~s(<article class="service-type empty">),
      ~s(<h2><code>),
      escape(type),
      ~s(</code></h2>),
      ~s(<p class="muted">No instances yet.</p>),
      ~s(</article>)
    ]
  end

  defp type_panel(type, instances) do
    [
      ~s(<article class="service-type">),
      ~s(<h2><code>),
      escape(type),
      ~s(</code> <span class="count">),
      escape(map_size(instances)),
      ~s(</span></h2>),
      ~s(<table class="instances">),
      ~s(<thead><tr>),
      ~s(<th>Instance</th>),
      ~s(<th>Target</th>),
      ~s(<th>Port</th>),
      ~s(<th>Addresses</th>),
      ~s(<th>TXT</th>),
      ~s(</tr></thead>),
      ~s(<tbody>),
      Enum.map(Enum.sort(instances), fn {instance, details} ->
        instance_row(instance, details)
      end),
      ~s(</tbody>),
      ~s(</table>),
      ~s(</article>)
    ]
  end

  defp instance_row(instance, details) do
    short_instance =
      case String.split(instance, ".", parts: 2) do
        [first, _] -> first
        [only] -> only
      end

    target = details.srv && details.srv.target
    port = details.srv && details.srv.port
    addresses = details.addresses
    txt_strings = (details.txt && details.txt.strings) || []

    [
      ~s(<tr>),
      ~s(<td class="instance"><span class="short">),
      escape(short_instance),
      ~s(</span><span class="full">),
      escape(instance),
      ~s(</span></td>),
      ~s(<td>),
      escape(target),
      ~s(</td>),
      ~s(<td class="port">),
      escape(port),
      ~s(</td>),
      ~s(<td>),
      Enum.map(addresses, fn ip -> [~s(<code>), escape(format_ip(ip)), ~s(</code> )] end),
      ~s(</td>),
      ~s(<td class="txt">),
      txt_list(txt_strings),
      ~s(</td>),
      ~s(</tr>)
    ]
  end

  defp txt_list([]), do: ~s(<span class="muted">&mdash;</span>)

  defp txt_list(strings) do
    [
      ~s(<ul>),
      Enum.map(strings, fn s -> [~s(<li><code>), escape(s), ~s(</code></li>)] end),
      ~s(</ul>)
    ]
  end
end
