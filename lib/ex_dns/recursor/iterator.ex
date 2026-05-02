defmodule ExDns.Recursor.Iterator do
  @moduledoc """
  Iterative resolver — walks the DNS hierarchy from the closest known
  delegation down to the authoritative answer.

  ## Algorithm

  1. Compute the longest suffix of the qname that has a cached NS
     RRset (or fall back to root hints).
  2. Pick a server from that NS RRset whose A/AAAA glue we know
     (cached or supplied), query it with the original qname/qtype.
  3. Inspect the response:
     * AA=1 with answers — cache and return them.
     * Referral (AA=0, AUTHORITY contains NS records for a closer
       cut) — cache the new NS + glue, restart at step 2 with the
       closer cut.
     * CNAME chain crossing a zone — restart with the new qname.
     * NXDOMAIN — cache the negative response, return.
  4. Bound everything by `max_depth` (default 16) and `max_time_ms`
     (default 5000) to prevent infinite loops.

  This is a textbook (RFC 1034 §5) iterative resolver. It does NOT
  perform DNSSEC validation, nor query-name minimisation (that's
  RFC 9156, deferred).

  """

  alias ExDns.Message
  alias ExDns.Message.{Header, Question}
  alias ExDns.Recursor.{Cache, Client, RootHints}

  @max_depth 16
  @max_time_ms 5_000

  @doc """
  Resolves `qname`/`qtype` recursively.

  ### Returns

  * `{:ok, [record, …]}` — the answer RRset (possibly through CNAMEs).
  * `{:error, :nxdomain}` — name does not exist.
  * `{:error, :timeout}` — exceeded the time budget.
  * `{:error, :max_depth}` — followed too many delegations.
  * `{:error, reason}` — other transport failure.

  """
  @spec resolve(binary(), atom(), keyword()) ::
          {:ok, [struct()]} | {:error, atom()}
  def resolve(qname, qtype, options \\ []) do
    deadline = monotonic_ms() + Keyword.get(options, :max_time_ms, @max_time_ms)
    max_depth = Keyword.get(options, :max_depth, @max_depth)

    case Cache.lookup(qname, qtype) do
      {:hit, records} -> {:ok, records}
      :miss -> iterate(qname, qtype, max_depth, deadline, [])
    end
  end

  defp iterate(_qname, _qtype, 0, _deadline, _trace), do: {:error, :max_depth}

  defp iterate(qname, qtype, depth, deadline, trace) do
    if monotonic_ms() > deadline do
      {:error, :timeout}
    else
      query_servers_for(qname, qtype, depth, deadline, trace)
    end
  end

  defp query_servers_for(qname, qtype, depth, deadline, trace) do
    {ns_owner, ns_ips} = closest_known_servers(qname)

    case try_servers(ns_ips, qname, qtype, deadline) do
      {:ok, response} ->
        handle_response(response, qname, qtype, ns_owner, depth, deadline, trace)

      {:error, _} = error ->
        error
    end
  end

  defp handle_response(%Message{} = response, qname, qtype, _ns_owner, depth, deadline, trace) do
    cache_response(response, qname, qtype)

    cond do
      response.header.rc == 3 ->
        {:error, :nxdomain}

      response.header.aa == 1 and matches_question?(response, qname, qtype) ->
        {:ok, normalize_answers(response.answer)}

      cname_target = cname_in_answer(response, qname) ->
        # Restart resolution at the canonical name. Don't double-count
        # against depth here.
        case Cache.lookup(cname_target, qtype) do
          {:hit, records} -> {:ok, normalize_answers(response.answer) ++ records}
          :miss -> iterate(cname_target, qtype, depth - 1, deadline, [qname | trace])
        end

      delegation = referral_in_authority(response) ->
        # The response is a referral; cache the new NS + glue, then
        # try again from the closer cut.
        cache_referral(delegation, response.additional)
        iterate(qname, qtype, depth - 1, deadline, [qname | trace])

      true ->
        # No answer, no CNAME, no useful authority — give up on this
        # query.
        {:ok, normalize_answers(response.answer)}
    end
  end

  # Returns `{ancestor, ips}` — the ancestor of qname for which we
  # have NS records (or root if we have nothing closer), and the list
  # of IPs we know for those name servers.
  defp closest_known_servers(qname) do
    qname
    |> ancestors()
    |> Enum.find_value(fn ancestor ->
      case Cache.lookup(ancestor, :ns) do
        {:hit, ns_records} ->
          ips = ips_for_ns(ns_records)
          if ips == [], do: nil, else: {ancestor, ips}

        :miss ->
          nil
      end
    end) || {"", RootHints.ipv4_addresses()}
  end

  defp ancestors(name) do
    name = name |> String.trim_trailing(".") |> String.downcase(:ascii)
    do_ancestors(name, [name])
  end

  defp do_ancestors("", acc), do: Enum.reverse(acc)

  defp do_ancestors(name, acc) do
    case String.split(name, ".", parts: 2) do
      [_only] -> Enum.reverse(["" | acc])
      [_first, rest] -> do_ancestors(rest, [rest | acc])
    end
  end

  defp ips_for_ns(ns_records) do
    ns_records
    |> Enum.flat_map(fn %ExDns.Resource.NS{server: server} ->
      a = case Cache.lookup(server, :a) do
        {:hit, records} -> Enum.map(records, & &1.ipv4)
        :miss -> []
      end

      aaaa = case Cache.lookup(server, :aaaa) do
        {:hit, records} -> Enum.map(records, & &1.ipv6)
        :miss -> []
      end

      a ++ aaaa
    end)
    |> Enum.uniq()
  end

  defp try_servers([], _qname, _qtype, _deadline), do: {:error, :no_servers}

  defp try_servers([ip | rest], qname, qtype, deadline) do
    if monotonic_ms() > deadline do
      {:error, :timeout}
    else
      query = build_query(qname, qtype)

      case Client.query(ip, query, udp_timeout: 1_500, tcp_timeout: 3_000) do
        {:ok, response} -> {:ok, response}
        {:error, _} -> try_servers(rest, qname, qtype, deadline)
      end
    end
  end

  defp build_query(qname, qtype) do
    %Message{
      header: %Header{
        id: :rand.uniform(65_535),
        qr: 0,
        oc: 0,
        aa: 0,
        tc: 0,
        rd: 0,
        ra: 0,
        ad: 0,
        cd: 0,
        rc: 0,
        qc: 1,
        anc: 0,
        auc: 0,
        adc: 1
      },
      question: %Question{host: qname, type: qtype, class: :in},
      answer: [],
      authority: [],
      additional: [
        %ExDns.Resource.OPT{
          payload_size: 1232,
          extended_rcode: 0,
          version: 0,
          dnssec_ok: 0,
          z: 0,
          options: []
        }
      ]
    }
  end

  defp matches_question?(%Message{question: %Question{host: host, type: type}}, qname, qtype) do
    String.downcase(host, :ascii) == String.downcase(qname, :ascii) and type == qtype
  end

  defp matches_question?(_, _, _), do: false

  defp cname_in_answer(%Message{answer: answer}, qname) do
    Enum.find_value(answer, nil, fn
      %ExDns.Resource.CNAME{name: name, server: target} ->
        if String.downcase(name, :ascii) == String.downcase(qname, :ascii), do: target, else: nil

      _ ->
        nil
    end)
  end

  defp referral_in_authority(%Message{authority: authority}) do
    ns_records = Enum.filter(authority, &match?(%ExDns.Resource.NS{}, &1))
    if ns_records == [], do: nil, else: ns_records
  end

  # ----- caching helpers ---------------------------------------------

  defp cache_response(response, _qname, _qtype) do
    cache_section(response.answer)
    cache_section(response.authority)
    cache_section(response.additional)
  end

  defp cache_referral(ns_records, additional) do
    cache_section(ns_records)
    cache_section(additional)
  end

  defp cache_section(records) when is_list(records) do
    records
    |> Enum.reject(&match?(%ExDns.Resource.OPT{}, &1))
    |> Enum.group_by(fn record -> {record.name, type_of(record)} end)
    |> Enum.each(fn {{name, type}, group} ->
      ttl = group |> Enum.map(& &1.ttl) |> Enum.min()
      Cache.put(name, type, group, ttl || 0)
    end)
  end

  defp type_of(%module{}) do
    module
    |> Module.split()
    |> List.last()
    |> String.downcase()
    |> String.to_existing_atom()
  end

  defp normalize_answers(records) do
    Enum.map(records, fn record ->
      case Map.get(record, :class) do
        :internet -> %{record | class: :in}
        _ -> record
      end
    end)
  end

  defp monotonic_ms, do: :erlang.monotonic_time(:millisecond)
end
