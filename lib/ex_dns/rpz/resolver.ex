defmodule ExDns.RPZ.Resolver do
  @moduledoc """
  Resolver wrapper that consults the active RPZ rule set
  before falling through to the underlying resolver.

  ## Behaviour

  For each request:

  1. Look up the qname in `ExDns.RPZ.Store.rules/0` via
     `ExDns.RPZ.Match.find/2`.
  2. On a match, materialise the rule's action into a
     response and return immediately:

     | Action          | Response                                            |
     |-----------------|-----------------------------------------------------|
     | `:nxdomain`     | rcode 3, empty answer                               |
     | `:nodata`       | rcode 0, empty answer                               |
     | `:passthru`     | fall through to the underlying resolver (allow-list)|
     | `:drop`         | return `nil` — listener silently drops              |
     | `:tcp_only`     | TC=1, empty answer (forces TCP retry)               |
     | `{:redirect, target}` | a single CNAME pointing at `target`           |
     | `{:synthesise, records}` | echo the supplied records as the answer    |

  3. On no match, defer to the underlying resolver
     (`ExDns.Resolver.Default` by default).

  ## Configuration

      config :ex_dns,
        resolver_module: ExDns.RPZ.Resolver,
        rpz: [
          enabled: true,
          underlying: ExDns.Resolver.Default
        ]

  Loading rule data into `ExDns.RPZ.Store` is the operator's
  job — typically by parsing one or more RPZ zone files at
  startup and calling `Store.put/1`.

  ## Telemetry

  `[:ex_dns, :rpz, :match]` fires on every query, with
  metadata `%{action, qname, qtype, source}` (`:source` is
  `:rpz` on a match, `:underlying` on fall-through).
  """

  alias ExDns.Message
  alias ExDns.Message.Header
  alias ExDns.Request
  alias ExDns.Resource.{A, AAAA, CNAME}
  alias ExDns.RPZ.{Match, Rule, Store}

  @doc """
  Resolve a request through the RPZ layer. Same shape as
  `ExDns.Resolver.Default.resolve/1`.
  """
  @spec resolve(Request.t() | Message.t()) :: Message.t() | nil
  def resolve(%Request{message: message} = request) do
    do_resolve(message, request)
  end

  def resolve(%Message{} = message) do
    do_resolve(message, nil)
  end

  defp do_resolve(%Message{question: question} = message, request) do
    case Match.find(question.host, Store.rules()) do
      {:match, %Rule{} = rule} ->
        :telemetry.execute(
          [:ex_dns, :rpz, :match],
          %{count: 1},
          %{
            action: action_tag(rule.action),
            qname: question.host,
            qtype: question.type,
            source: :rpz
          }
        )

        materialise(rule, message, request)

      :no_match ->
        :telemetry.execute(
          [:ex_dns, :rpz, :match],
          %{count: 1},
          %{action: :passthru, qname: question.host, qtype: question.type, source: :underlying}
        )

        defer(message, request)
    end
  end

  # ----- action materialisation ------------------------------------

  defp materialise(%Rule{action: :nxdomain}, msg, _req), do: blank_response(msg, 3, [])
  defp materialise(%Rule{action: :nodata}, msg, _req), do: blank_response(msg, 0, [])
  defp materialise(%Rule{action: :passthru}, msg, req), do: defer(msg, req)
  defp materialise(%Rule{action: :drop}, _msg, _req), do: nil

  defp materialise(%Rule{action: :tcp_only}, %Message{header: %Header{} = header} = msg, _req) do
    %Message{
      msg
      | header: %Header{
          header
          | qr: 1,
            aa: 1,
            tc: 1,
            ra: 0,
            ad: 0,
            cd: 0,
            rc: 0,
            anc: 0,
            auc: 0,
            adc: 0
        },
        answer: [],
        authority: [],
        additional: []
    }
  end

  defp materialise(%Rule{action: {:redirect, target}, ttl: ttl}, msg, _req) do
    cname = %CNAME{
      name: msg.question.host,
      ttl: ttl,
      class: :in,
      server: target
    }

    blank_response(msg, 0, [cname])
  end

  defp materialise(%Rule{action: {:synthesise, records}, ttl: ttl}, msg, _req) do
    qname = msg.question.host

    rebound =
      Enum.map(records, fn r ->
        case r do
          %A{} = a -> %A{a | name: qname, ttl: ttl, class: :in}
          %AAAA{} = a -> %AAAA{a | name: qname, ttl: ttl, class: :in}
          other -> %{other | name: qname, ttl: ttl}
        end
      end)

    blank_response(msg, 0, rebound)
  end

  defp blank_response(%Message{header: %Header{} = header} = msg, rcode, answer) do
    %Message{
      msg
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

  defp defer(message, nil), do: underlying().resolve(message)
  defp defer(_message, request), do: underlying().resolve(request)

  defp action_tag(:nxdomain), do: :nxdomain
  defp action_tag(:nodata), do: :nodata
  defp action_tag(:passthru), do: :passthru
  defp action_tag(:drop), do: :drop
  defp action_tag(:tcp_only), do: :tcp_only
  defp action_tag({:redirect, _}), do: :redirect
  defp action_tag({:synthesise, _}), do: :synthesise

  defp underlying do
    Application.get_env(:ex_dns, :rpz, [])
    |> Keyword.get(:underlying, ExDns.Resolver.Default)
  end
end
