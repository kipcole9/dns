defmodule ExDns.Resolver.Plugins do
  @moduledoc """
  Resolver wrapper that consults the plugin registry's route
  table before delegating to the underlying resolver.

  ## Behaviour

  For each request:

  1. `ExDns.Plugin.Registry.match/1` does a single
     longest-prefix lookup. At most one route matches.

  2. On a match, calls
     `plugin_module.policy_resolve(request, route)`. The
     return values:

     | Return                          | Effect                                    |
     |---------------------------------|-------------------------------------------|
     | `:cont`                         | Fall through to the underlying resolver.  |
     | `{:halt, %Message{}}`           | Send the message as-is.                   |
     | `{:halt, :nxdomain}`            | Synthesise authoritative NXDOMAIN.        |
     | `{:halt, {:redirect, ip}}`      | Synthesise A/AAAA pointing at `ip`.       |

  3. On `:none` (no plugin claimed the route), defer to the
     underlying resolver. **Pass-through is the floor** —
     this MUST behave identically to the underlying resolver
     for unmatched queries.

  ## Configuration

      config :ex_dns,
        resolver_module: ExDns.Resolver.Plugins,
        plugins: [...],
        plugin_pipeline: [
          underlying: ExDns.Resolver.Default
        ]

  Set `:underlying` to whichever resolver you'd otherwise
  configure as `:resolver_module`.

  ## Telemetry

  `[:ex_dns, :resolver, :plugins, :match]` fires on every
  query with metadata `%{decision, qname, qtype, source_ip,
  plugin_slug}`. `:decision` is one of `:passthru`,
  `:plugin_cont`, `:plugin_halt`.
  """

  alias ExDns.Message
  alias ExDns.Message.Header
  alias ExDns.Plugin.Registry
  alias ExDns.Request
  alias ExDns.Resource.{A, AAAA}

  @doc """
  Resolve a request via the plugin pipeline.

  ### Arguments

  * `request_or_message` — `%ExDns.Request{}` or
    `%ExDns.Message{}` (the latter cannot match plugin
    routes since it has no `:source_ip`, so it's passed
    straight to the underlying resolver).
  """
  @spec resolve(Request.t() | Message.t()) :: Message.t() | nil
  def resolve(%Request{} = request) do
    cond do
      ExDns.PauseMode.paused?() ->
        # Big-red-button: every plugin is bypassed; queries
        # flow straight to the underlying resolver. The
        # operator-facing `paused?/0` flag is checked once
        # per query and is cheap (`:persistent_term`).
        emit(:passthru, request, :paused)
        defer(request)

      true ->
        case Registry.match(request) do
          {:ok, plugin_module, route} ->
            emit(:plugin_cont, request, plugin_module)
            run_plugin(plugin_module, request, route)

          :none ->
            emit(:passthru, request, nil)
            defer(request)
        end
    end
  end

  def resolve(%Message{} = message) do
    underlying().resolve(message)
  end

  defp run_plugin(module, request, route) do
    case module.policy_resolve(request, route) do
      :cont ->
        defer(request)

      {:halt, %Message{} = response} ->
        emit(:plugin_halt, request, module)
        response

      {:halt, :nxdomain} ->
        emit(:plugin_halt, request, module)
        synthesise_nxdomain(request)

      {:halt, {:redirect, ip}} ->
        emit(:plugin_halt, request, module)
        synthesise_redirect(request, ip)
    end
  end

  defp defer(%Request{} = request), do: underlying().resolve(request)

  defp underlying do
    Application.get_env(:ex_dns, :plugin_pipeline, [])
    |> Keyword.get(:underlying, ExDns.Resolver.Default)
  end

  # ----- response synthesis -----------------------------------------

  defp synthesise_nxdomain(%Request{message: message}) do
    blank(message, 3, [])
  end

  defp synthesise_redirect(%Request{message: message}, ip) do
    qname = message.question.host
    record = build_address_record(qname, ip)

    if record == nil do
      blank(message, 0, [])
    else
      blank(message, 0, [record])
    end
  end

  defp build_address_record(qname, {a, b, c, d}) do
    %A{name: qname, ttl: 60, class: :in, ipv4: {a, b, c, d}}
  end

  defp build_address_record(qname, {_, _, _, _, _, _, _, _} = ipv6) do
    %AAAA{name: qname, ttl: 60, class: :in, ipv6: ipv6}
  end

  defp build_address_record(_, _), do: nil

  defp blank(%Message{header: %Header{} = header} = message, rcode, answer) do
    %Message{
      message
      | header: %Header{
          header
          | qr: 1,
            aa: 1,
            ra: 0,
            ad: 0,
            cd: 0,
            rc: rcode,
            anc: length(answer),
            auc: 0,
            adc: 0
        },
        answer: answer,
        authority: [],
        additional: []
    }
  end

  defp emit(decision, request, plugin_module) do
    :telemetry.execute(
      [:ex_dns, :resolver, :plugins, :match],
      %{count: 1},
      %{
        decision: decision,
        qname: get_in(request.message.question, [Access.key(:host)]),
        qtype: get_in(request.message.question, [Access.key(:type)]),
        source_ip: request.source_ip,
        plugin_slug: plugin_slug(plugin_module)
      }
    )
  end

  defp plugin_slug(nil), do: nil

  defp plugin_slug(module) do
    case module.metadata() do
      %{slug: slug} -> slug
      _ -> nil
    end
  rescue
    _ -> nil
  end
end
