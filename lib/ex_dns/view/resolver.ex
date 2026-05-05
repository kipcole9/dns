defmodule ExDns.View.Resolver do
  @moduledoc """
  Resolver wrapper that selects a per-client view (BIND
  `view`-style) and answers from the view's zone data.

  ## Behaviour

  For each request:

  1. Classify the client by source IP + TSIG key name.
  2. Walk the configured `:views` list in order; pick the
     first whose match clauses fit the client.
  3. If a view matches and its storage holds a zone covering
     the qname, answer from that view's zone data.
  4. If no view matches OR the matching view doesn't host the
     qname:
     * Strict mode (`view_fallthrough: false`, default): return
       REFUSED. Each view is its own self-contained universe.
     * Inherit mode (`view_fallthrough: true`): fall through to
       the default resolver and the global Storage. Views act
       as deltas on top of a shared baseline.

  ## Wiring

      config :ex_dns,
        resolver_module: ExDns.View.Resolver,
        view_fallthrough: true,
        views: [
          %{
            name: "internal",
            match: [{:cidr, {{10, 0, 0, 0}, 8}}],
            zones: [...]   # used by the loader, not by this module
          },
          %{
            name: "external",
            match: [:any],
            zones: [...]
          }
        ]

  Per-view zone *loading* (filling `View.Storage`) is the
  operator's responsibility — typically driven from the
  `:zones` field of each view's config by a startup hook.
  This module just consults whatever's already in
  `View.Storage`.

  ## Telemetry

  Emits `[:ex_dns, :view, :selected]` with `%{view: name | nil,
  qname, qtype}` on every request so dashboards can track view
  hit rates.
  """

  alias ExDns.Message
  alias ExDns.Message.Header
  alias ExDns.Request
  alias ExDns.View
  alias ExDns.View.Storage, as: VS

  @doc """
  Resolve a request through the view layer.

  Implements the same shape as `ExDns.Resolver.Default.resolve/1`.

  ### Arguments

  * `request_or_message` — `%ExDns.Request{}` or
    `%ExDns.Message{}`.

  ### Returns

  * `%ExDns.Message{}` — the response.
  """
  @spec resolve(Request.t() | Message.t()) :: Message.t()
  def resolve(%Request{} = request) do
    view = View.select(request.source_ip, tsig_key_name(request))

    :telemetry.execute(
      [:ex_dns, :view, :selected],
      %{count: 1},
      %{
        view: if(view, do: view.name, else: nil),
        qname: request.message.question.host,
        qtype: request.message.question.type
      }
    )

    case answer_from_view(view, request.message) do
      {:ok, response} -> response
      :miss -> fallthrough(request)
    end
  end

  def resolve(%Message{} = message) do
    # Direct-Message callers (mostly tests) lose the view layer
    # — there's no source-IP context.
    fallback().resolve(message)
  end

  # ----- view-side answering ---------------------------------------

  defp answer_from_view(nil, _message), do: :miss

  defp answer_from_view(%View{name: view_name}, %Message{question: question} = message) do
    case VS.lookup(view_name, question.host, question.type) do
      {:ok, _apex, records} ->
        {:ok, build_response(message, records)}

      {:error, :nxdomain} ->
        # The view OWNS this apex but has no record at this
        # name+type. Strict mode: NXDOMAIN/NODATA right here.
        # Inherit mode: still serve NXDOMAIN — falling through
        # would expose the global zone's data, which defeats
        # split-horizon.
        {:ok, nxdomain_response(message)}

      :miss ->
        # The view doesn't host any zone covering qname.
        # Defer to the fall-through policy.
        :miss
    end
  end

  defp fallthrough(%Request{} = request) do
    if Application.get_env(:ex_dns, :view_fallthrough, false) do
      fallback().resolve(request)
    else
      refused_response(request.message)
    end
  end

  # ----- response builders -----------------------------------------

  defp build_response(%Message{header: %Header{} = header} = query, records) do
    %Message{
      query
      | header: %Header{
          header
          | qr: 1,
            aa: 1,
            ra: 0,
            ad: 0,
            cd: 0,
            rc: 0,
            anc: length(records),
            auc: 0,
            adc: 0
        },
        answer: records,
        authority: [],
        additional: []
    }
  end

  defp nxdomain_response(%Message{header: %Header{} = header} = query) do
    %Message{
      query
      | header: %Header{
          header
          | qr: 1,
            aa: 1,
            ra: 0,
            ad: 0,
            cd: 0,
            rc: 3,
            anc: 0,
            auc: 0,
            adc: 0
        },
        answer: [],
        authority: [],
        additional: []
    }
  end

  defp refused_response(%Message{header: %Header{} = header} = query) do
    %Message{
      query
      | header: %Header{
          header
          | qr: 1,
            aa: 0,
            ra: 0,
            ad: 0,
            cd: 0,
            rc: 5,
            anc: 0,
            auc: 0,
            adc: 0
        },
        answer: [],
        authority: [],
        additional: []
    }
  end

  defp tsig_key_name(%Request{} = _request) do
    # TSIG-key-based view selection is a follow-up — needs the
    # listener to thread the verified key name into the
    # `Request` struct (a small field addition). For now,
    # source-IP-based view selection is the supported surface.
    nil
  end

  defp fallback do
    Application.get_env(:ex_dns, :view_fallback_resolver, ExDns.Resolver.Default)
  end
end
