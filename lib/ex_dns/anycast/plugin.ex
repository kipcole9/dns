defmodule ExDns.Anycast.Plugin do
  @moduledoc """
  Anycast / regional-routing plugin.

  Maps source-IP CIDRs to synthesised A / AAAA answers,
  enabling per-region answer selection without recursing
  through the standard resolver. This is the spiritual
  successor to `ExDns.Policy.SourceIp`, ported onto the
  CIDR-routed plugin framework so it composes with BlackHole
  and any other policy plugin.

  ## Configuration

      config :ex_dns, :anycast,
        regions: [
          %{
            id: :eu,
            cidrs: [{{198, 51, 100, 0}, 24}],
            qname_suffix: "cdn.example",
            answers: %{
              a: {192, 0, 2, 1},
              aaaa: {0x2001, 0xDB8, 0, 0, 0, 0, 0, 1}
            }
          },
          %{
            id: :us,
            cidrs: [{{203, 0, 113, 0}, 24}],
            qname_suffix: "cdn.example",
            answers: %{a: {192, 0, 2, 2}}
          }
        ]

  ## Behaviour

  * `routes/0` returns one route per region, each scoped by
    the region's CIDRs and (optionally) `qname_suffix`.

  * `policy_resolve/2` matches the request's qtype against
    the region's `answers` map. Hit → halt with a
    synthesised authoritative response. Miss → `:cont`
    (chain falls through to the underlying resolver).

  ## Resources (UI tab)

  * `:regions` — list of `{id, cidrs, qname_suffix, answers}`
    rows for the generic plugin tab.
  """

  @behaviour ExDns.Plugin
  @behaviour ExDns.Plugin.Policy

  alias ExDns.Message
  alias ExDns.Message.Header
  alias ExDns.Resource.{A, AAAA}

  @impl ExDns.Plugin
  def metadata do
    %{
      slug: :anycast,
      name: "Anycast",
      version: "0.1.0",
      ui: %{
        title: "Anycast",
        view: :table,
        resources: [:regions]
      }
    }
  end

  @impl ExDns.Plugin
  def get_resource(:regions), do: {:ok, regions_for_ui()}
  def get_resource(_), do: {:error, :not_found}

  @impl ExDns.Plugin.Policy
  def routes do
    Enum.map(configured_regions(), fn region ->
      %{
        cidrs: region.cidrs,
        qtypes: Map.keys(region.answers),
        qname_suffix: region[:qname_suffix],
        priority: Map.get(region, :priority, 50)
      }
    end)
  end

  @impl ExDns.Plugin.Policy
  def policy_resolve(request, route) do
    case region_for_route(route) do
      nil ->
        :cont

      region ->
        synthesise(request, region)
    end
  end

  # ----- region lookup ----------------------------------------------

  defp region_for_route(route) do
    cidrs = Map.get(route, :cidrs)
    suffix = Map.get(route, :qname_suffix)

    Enum.find(configured_regions(), fn region ->
      region.cidrs == cidrs and region[:qname_suffix] == suffix
    end)
  end

  defp configured_regions do
    Application.get_env(:ex_dns, :anycast, [])
    |> Keyword.get(:regions, [])
    |> Enum.map(&normalise_region/1)
  end

  defp normalise_region(%{} = region) do
    %{
      id: Map.get(region, :id),
      cidrs: Map.fetch!(region, :cidrs),
      qname_suffix: Map.get(region, :qname_suffix),
      answers: Map.get(region, :answers, %{}),
      priority: Map.get(region, :priority, 50),
      ttl: Map.get(region, :ttl, 60)
    }
  end

  # ----- response synthesis -----------------------------------------

  defp synthesise(%ExDns.Request{message: message}, region) do
    qtype = message.question.type
    qname = message.question.host

    case Map.get(region.answers, qtype) do
      nil ->
        :cont

      target ->
        records = build_records(qtype, qname, target, region.ttl)

        if records == [] do
          :cont
        else
          {:halt, build_response(message, records)}
        end
    end
  end

  defp build_records(:a, qname, target, ttl) do
    target
    |> List.wrap()
    |> Enum.flat_map(fn
      {_, _, _, _} = ipv4 -> [%A{name: qname, ttl: ttl, class: :in, ipv4: ipv4}]
      _ -> []
    end)
  end

  defp build_records(:aaaa, qname, target, ttl) do
    target
    |> List.wrap()
    |> Enum.flat_map(fn
      {_, _, _, _, _, _, _, _} = ipv6 -> [%AAAA{name: qname, ttl: ttl, class: :in, ipv6: ipv6}]
      _ -> []
    end)
  end

  defp build_records(_, _, _, _), do: []

  defp build_response(%Message{header: %Header{} = header, question: question} = message, records) do
    %Message{
      message
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
        question: question,
        answer: records,
        authority: [],
        additional: []
    }
  end

  # ----- UI rows ----------------------------------------------------

  defp regions_for_ui do
    Enum.map(configured_regions(), fn region ->
      %{
        "id" => to_string(region.id || ""),
        "cidrs" => Enum.map(region.cidrs, &format_cidr/1),
        "qname_suffix" => region.qname_suffix || "",
        "answers" => format_answers(region.answers),
        "ttl" => region.ttl
      }
    end)
  end

  defp format_cidr({ip, prefix}), do: "#{format_ip(ip)}/#{prefix}"

  defp format_ip({_, _, _, _} = ip), do: :inet.ntoa(ip) |> to_string()
  defp format_ip({_, _, _, _, _, _, _, _} = ip), do: :inet.ntoa(ip) |> to_string()

  defp format_answers(%{} = answers) do
    answers
    |> Enum.map(fn {qtype, target} ->
      "#{qtype}=#{format_target(target)}"
    end)
    |> Enum.join(" ")
  end

  defp format_target(target) when is_list(target),
    do: target |> Enum.map(&format_ip/1) |> Enum.join(",")

  defp format_target(target) when is_tuple(target), do: format_ip(target)
  defp format_target(other), do: inspect(other)
end
