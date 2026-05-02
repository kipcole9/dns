defmodule ExDns.Policy.SourceIp do
  @moduledoc """
  Source-IP policy.

  Maps inbound CIDR ranges to synthetic answers, enabling poor-man's
  Anycast / regional routing without recursing through the standard
  resolver: pick a different answer per source network.

  ## Configuration

      config :ex_dns,
        resolver: ExDns.Resolver.Policy,
        policies: [
          {ExDns.Policy.SourceIp,
            # Order matters — first match wins.
            table: [
              {{{198, 51, 100, 0}, 24}, %{a: {192, 0, 2, 1}}},
              {{{203, 0,   113, 0}, 24}, %{a: {192, 0, 2, 2}}}
            ]}
        ]

  Each table entry is `{cidr, answers}` where:

  * `cidr` is `{ip4_address, prefix_length}` for IPv4 or
    `{ip6_address, prefix_length}` for IPv6.
  * `answers` is a map keyed by qtype atom — `:a`, `:aaaa`, … — with
    a value the policy knows how to synthesize:
    * `{a, b, c, d}` — emitted as a single A record
    * `{a, b, c, d, e, f, g, h}` — emitted as a single AAAA record
    * a list of either — multiple records

  When the source IP matches a CIDR and the qtype has a configured
  answer, the policy halts the chain with a NOERROR/AA response.
  Otherwise it returns `:continue` and the chain proceeds.

  ## Limitations

  * Class is forced to `:in`.
  * TTL defaults to 60 seconds; pass `:ttl` in the answer map (e.g.
    `%{a: {{192, 0, 2, 1}, ttl: 30}}`) to override per-entry.
  * Only A and AAAA are synthesized in this version. CNAME / TXT / MX
    can be added by extending `synthesize/3`.

  """

  @behaviour ExDns.Policy

  alias ExDns.Message
  alias ExDns.Message.Header
  alias ExDns.Request

  @impl ExDns.Policy
  def init(opts) do
    table =
      opts
      |> Keyword.get(:table, [])
      |> Enum.map(&compile_entry/1)

    %{table: table, default_ttl: Keyword.get(opts, :default_ttl, 60)}
  end

  @impl ExDns.Policy
  def resolve(%Request{source_ip: nil}, _state), do: :continue

  def resolve(%Request{source_ip: source_ip, message: message} = _request, state) do
    %Message{question: question} = message

    cond do
      is_nil(question) ->
        :continue

      true ->
        case find_match(state.table, source_ip) do
          {:ok, answers} ->
            case synthesize(question.type, answers, question, state.default_ttl) do
              [] -> :continue
              records -> {:halt, build_response(message, records)}
            end

          :no_match ->
            :continue
        end
    end
  end

  # ----- helpers ------------------------------------------------------

  defp find_match(table, source_ip) do
    Enum.find_value(table, :no_match, fn {cidr, answers} ->
      if cidr_match?(cidr, source_ip), do: {:ok, answers}, else: nil
    end)
  end

  defp compile_entry({{ip, prefix}, answers}) when is_tuple(ip) and is_integer(prefix) do
    {{ip, prefix}, answers}
  end

  @doc """
  Returns true when `address` falls inside `{network_ip, prefix_length}`.

  Both IPv4 (`{a,b,c,d}` + prefix 0–32) and IPv6 (`{a..h}` + prefix
  0–128) are supported.
  """
  @spec cidr_match?({tuple(), non_neg_integer()}, tuple()) :: boolean()
  def cidr_match?({network, prefix}, address)
      when tuple_size(network) == 4 and tuple_size(address) == 4 do
    bitstring_match?(ip4_to_bits(network), ip4_to_bits(address), prefix)
  end

  def cidr_match?({network, prefix}, address)
      when tuple_size(network) == 8 and tuple_size(address) == 8 do
    bitstring_match?(ip6_to_bits(network), ip6_to_bits(address), prefix)
  end

  def cidr_match?(_, _), do: false

  defp bitstring_match?(_, _, 0), do: true

  defp bitstring_match?(<<a::1, ar::bitstring>>, <<b::1, br::bitstring>>, prefix) when prefix > 0 do
    a == b and bitstring_match?(ar, br, prefix - 1)
  end

  defp ip4_to_bits({a, b, c, d}), do: <<a, b, c, d>>

  defp ip6_to_bits({a, b, c, d, e, f, g, h}) do
    <<a::16, b::16, c::16, d::16, e::16, f::16, g::16, h::16>>
  end

  # ----- answer synthesis --------------------------------------------

  defp synthesize(:a, %{a: target}, question, ttl) do
    target
    |> List.wrap()
    |> Enum.map(fn ipv4 ->
      %ExDns.Resource.A{name: question.host, ttl: ttl, class: :in, ipv4: ipv4}
    end)
  end

  defp synthesize(:aaaa, %{aaaa: target}, question, ttl) do
    target
    |> List.wrap()
    |> Enum.map(fn ipv6 ->
      %ExDns.Resource.AAAA{name: question.host, ttl: ttl, class: :in, ipv6: ipv6}
    end)
  end

  defp synthesize(_other, _answers, _question, _ttl), do: []

  defp build_response(%Message{header: %Header{} = header, question: question} = message, records) do
    new_header = %Header{
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
    }

    %Message{
      message
      | header: new_header,
        question: question,
        answer: records,
        authority: [],
        additional: []
    }
  end
end
