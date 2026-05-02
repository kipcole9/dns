defmodule ExDns.Resolver.Default do
  @moduledoc """
  Default authoritative resolver.

  Given a decoded DNS query `%ExDns.Message{}`, produces the
  corresponding response message by looking up records in
  `ExDns.Storage.ETS`. The resolver is authoritative-only — it does not
  recurse on behalf of clients.

  ## Response shape

  * The header is copied from the query with `qr` set to `1` (response),
    `aa` set to `1` (authoritative answer when the queried name falls
    under a zone we own), `ra` set to `0` (no recursion offered), and
    `rc` set to `0` (NOERROR), `3` (NXDOMAIN), or `4` (NOTIMP) as
    appropriate.

  * The question section is echoed back unchanged.

  * The answer section holds the matching RRset, when one exists.

  * The authority section is empty in this first cut (later: zone SOA
    on NXDOMAIN/NODATA; NS delegation when below a cut).

  * The additional section is empty in this first cut (later: glue A/AAAA
    for NS targets, plus EDNS0 OPT).

  Wildcards, CNAME chasing, and NS delegation are not yet implemented.

  """

  alias ExDns.Message
  alias ExDns.Message.{Header, Question}
  alias ExDns.Request
  alias ExDns.Resource.OPT
  alias ExDns.Storage

  # Default UDP payload size advertised in our OPT response when the
  # client did not pin one. 1232 is the EDNS payload size recommended by
  # the DNS Flag Day 2020 to stay under the typical 1500-byte path MTU
  # minus IP/UDP headers and a safety margin.
  @default_payload_size 1232

  @doc """
  Resolves a query message and returns the response message.

  ### Arguments

  * `message` is the decoded query `%ExDns.Message{}`.

  ### Returns

  * A response `%ExDns.Message{}`. The caller is responsible for
    encoding it onto the wire.

  """
  @spec resolve(Message.t() | Request.t()) :: Message.t()

  def resolve(%Request{message: message}), do: resolve(message)

  def resolve(%Message{header: %Header{qr: 0, oc: 0}, question: %Question{} = question} = message) do
    answer_query(message, question)
  end

  # Inverse query (obsolete) — return NOTIMP.
  def resolve(%Message{header: %Header{qr: 0, oc: 1}} = message) do
    set_response(message, [], rcode: 4, aa: 0, authority: [])
  end

  # NOTIFY (RFC 1996, opcode 4) — acknowledge with NOERROR. AA is set
  # if we are authoritative for the named zone. We do not currently
  # trigger a refresh because we have no secondary-zone configuration;
  # that's a follow-up.
  def resolve(%Message{header: %Header{qr: 0, oc: 4}, question: question} = message) do
    require Logger

    aa =
      case question do
        %Question{host: host} ->
          Logger.info("Received NOTIFY for #{inspect(host)}")
          if Storage.find_zone(host), do: 1, else: 0

        _ ->
          Logger.info("Received NOTIFY (no question section)")
          0
      end

    set_response(message, [], rcode: 0, aa: aa, authority: [])
  end

  # Anything else (status, update, …) — NOTIMP for now.
  def resolve(%Message{header: %Header{qr: 0}} = message) do
    set_response(message, [], rcode: 4, aa: 0, authority: [])
  end

  # Maximum length of a CNAME chain we'll follow. Anything beyond this
  # is treated as a loop and we return whatever we accumulated so far
  # rather than chase forever.
  @max_cname_depth 8

  defp answer_query(message, %Question{host: qname, type: qtype} = question) do
    # Check for an NS delegation cut at or above qname before doing
    # normal resolution. If qname is below a cut we are not the
    # authoritative server and respond with a referral.
    case Storage.find_delegation(qname) do
      {:ok, _apex, delegation_name, ns_records}
      when delegation_name != qname or qtype != :ns ->
        respond_with_referral(message, ns_records)

      _ ->
        answer_query_authoritative(message, question)
    end
  end

  # IXFR (RFC 1995) — we do not maintain a journal of changes, so we
  # always fall back to a full AXFR per RFC 1995 §2 ("If the server
  # cannot provide an incremental zone transfer, it should respond with
  # the full zone").
  defp answer_query_authoritative(message, %Question{type: :ixfr} = question) do
    answer_query_authoritative(message, %{question | type: :axfr})
  end

  defp answer_query_authoritative(message, %Question{host: qname, type: :axfr}) do
    qname = String.downcase(qname, :ascii) |> String.trim_trailing(".")

    case Storage.find_zone(qname) do
      ^qname ->
        case Storage.dump_zone(qname) do
          {:ok, [%ExDns.Resource.SOA{} = soa | _] = records} ->
            # RFC 5936 §2.2: AXFR response is SOA, all RRs, SOA.
            answer = Enum.map(records ++ [soa], &normalize_class/1)
            set_response(message, answer, rcode: 0, aa: 1, authority: [])

          {:ok, _} ->
            # Zone exists but has no SOA — refuse.
            set_response(message, [], rcode: 5, aa: 0, authority: [])

          {:error, :not_loaded} ->
            set_response(message, [], rcode: 5, aa: 0, authority: [])
        end

      _ ->
        # AXFR can only be served for a zone we are authoritative for at
        # the apex; otherwise REFUSED.
        set_response(message, [], rcode: 5, aa: 0, authority: [])
    end
  end

  defp answer_query_authoritative(message, %Question{host: qname, type: :any}) do
    case Storage.lookup_any(qname) do
      {:ok, _apex, records} ->
        records = Enum.map(records, &normalize_class/1)
        set_response(message, records, rcode: 0, aa: 1, authority: [])

      {:error, :nxdomain} ->
        case Storage.find_zone(qname) do
          nil -> set_response(message, [], rcode: 3, aa: 0, authority: [])
          apex -> set_response(message, [], rcode: 3, aa: 1, authority: soa_authority(apex))
        end
    end
  end

  defp answer_query_authoritative(message, %Question{host: qname, type: qtype}) do
    case resolve_with_cname_chasing(qname, qtype, @max_cname_depth, []) do
      {:ok, records} ->
        records = Enum.map(records, &normalize_class/1)
        set_response(message, records, rcode: 0, aa: 1, authority: [])

      {:nodata, apex} ->
        # NODATA — name exists in the zone but has no records of the
        # requested type. RFC 2308 says we should put the apex SOA in
        # the authority section so the client can compute the negative
        # caching TTL.
        set_response(message, [],
          rcode: 0,
          aa: 1,
          authority: soa_authority(apex)
        )

      {:partial, records, apex} ->
        # We followed at least one CNAME but the chain ended in NODATA
        # for the requested type. Per RFC 1034 §4.3.2, return what we
        # gathered as the answer with rcode = NOERROR; include the SOA
        # in authority for negative caching of the trailing name.
        records = Enum.map(records, &normalize_class/1)

        set_response(message, records,
          rcode: 0,
          aa: 1,
          authority: soa_authority(apex)
        )

      :nxdomain ->
        case Storage.find_zone(qname) do
          nil ->
            # Not authoritative for any suffix of qname. Return
            # NXDOMAIN with aa=0 and no SOA — clients should not cache
            # negatively against us.
            set_response(message, [], rcode: 3, aa: 0, authority: [])

          apex ->
            set_response(message, [],
              rcode: 3,
              aa: 1,
              authority: soa_authority(apex)
            )
        end
    end
  end

  # Returns one of:
  #   {:ok, records}                     — direct hit (incl. CNAME chain that fully resolved)
  #   {:nodata, apex}                    — name exists but no records of that type, no CNAME either
  #   {:partial, records, apex}          — followed at least one CNAME, target is NODATA
  #   :nxdomain                          — qname not present
  defp resolve_with_cname_chasing(_qname, _qtype, 0, accumulated) do
    # Depth budget exhausted — surface what we have without erroring.
    {:ok, accumulated}
  end

  defp resolve_with_cname_chasing(qname, qtype, depth, accumulated) do
    case Storage.lookup(qname, qtype) do
      {:ok, _apex, [_ | _] = records} ->
        {:ok, accumulated ++ records}

      {:ok, apex, []} when qtype != :cname ->
        # Name exists with no records of the requested type. Try CNAME.
        case Storage.lookup(apex, qname, :cname) do
          {:ok, _apex, [%ExDns.Resource.CNAME{server: target} = cname | _]} ->
            new_accumulated = accumulated ++ [cname]
            chase_cname(target, qtype, depth - 1, new_accumulated, apex)

          _ ->
            # Fall back to wildcard (RFC 4592). The wildcard target's
            # owner name is rewritten to qname before being returned.
            case wildcard_or_cname(qname, qtype) do
              {:ok, records} -> {:ok, accumulated ++ records}
              :miss -> cname_or_nodata_result(accumulated, apex)
            end
        end

      {:ok, apex, []} ->
        cname_or_nodata_result(accumulated, apex)

      {:error, :nxdomain} when accumulated == [] ->
        # Try wildcard before giving up.
        case wildcard_or_cname(qname, qtype) do
          {:ok, records} ->
            {:ok, records}

          :miss ->
            # If a wildcard exists for the ancestor but doesn't have
            # records of the requested type, the synthetic name is
            # considered present — answer NODATA, not NXDOMAIN.
            case Storage.wildcard_name_exists?(qname) do
              {:ok, apex} -> {:nodata, apex}
              false -> :nxdomain
            end
        end

      {:error, :nxdomain} ->
        # CNAME pointed to a name that doesn't exist; treat the chain
        # as partial and let the caller add SOA for negative caching.
        case Storage.find_zone(qname) do
          nil -> {:ok, accumulated}
          apex -> {:partial, accumulated, apex}
        end
    end
  end

  defp chase_cname(target, qtype, depth, accumulated, prior_apex) do
    case resolve_with_cname_chasing(target, qtype, depth, accumulated) do
      {:ok, _} = ok -> ok
      {:nodata, apex} -> {:partial, accumulated, apex}
      {:partial, _, _} = partial -> partial
      :nxdomain -> {:partial, accumulated, prior_apex}
    end
  end

  defp cname_or_nodata_result([], apex), do: {:nodata, apex}
  defp cname_or_nodata_result(accumulated, apex), do: {:partial, accumulated, apex}

  # Tries an RFC 4592 wildcard match for `qname` and `qtype`. Synthesised
  # records have their `:name` field rewritten to `qname`. Also handles
  # the case where the wildcard itself is a CNAME: it gets rewritten and
  # the chain is followed.
  defp wildcard_or_cname(qname, qtype) do
    case Storage.lookup_wildcard(qname, qtype) do
      {:ok, _apex, records} ->
        {:ok, Enum.map(records, fn record -> %{record | name: qname} end)}

      {:error, :nxdomain} ->
        # Wildcard might exist for CNAME at this name even when the
        # requested qtype does not match — chase through it.
        case Storage.lookup_wildcard(qname, :cname) do
          {:ok, _apex, [%ExDns.Resource.CNAME{server: target} = cname | _]} ->
            rewritten_cname = %{cname | name: qname}

            case resolve_with_cname_chasing(target, qtype, @max_cname_depth - 1, [rewritten_cname]) do
              {:ok, records} -> {:ok, records}
              _ -> {:ok, [rewritten_cname]}
            end

          _ ->
            :miss
        end
    end
  end

  # Returns a list containing the apex SOA (with class normalized for
  # the wire) when one is available, or `[]` otherwise.
  defp soa_authority(apex) do
    case Storage.lookup(apex, apex, :soa) do
      {:ok, _apex, records} -> Enum.map(records, &normalize_class/1)
      {:error, :nxdomain} -> []
    end
  end

  # Builds a referral response: empty answer, NS records in authority,
  # any in-zone A/AAAA glue in additional, AA cleared.
  defp respond_with_referral(message, ns_records) do
    ns_records = Enum.map(ns_records, &normalize_class/1)
    glue = collect_glue(ns_records)

    set_response(message, [], rcode: 0, aa: 0, authority: ns_records, additional: glue)
  end

  # For each NS record's target name, look up A and AAAA records in our
  # storage. Returns a list of glue records (possibly empty).
  defp collect_glue(ns_records) do
    Enum.flat_map(ns_records, fn %ExDns.Resource.NS{server: target} ->
      glue_for_target(target, :a) ++ glue_for_target(target, :aaaa)
    end)
  end

  defp glue_for_target(target, qtype) do
    case Storage.lookup(target, qtype) do
      {:ok, _apex, records} -> Enum.map(records, &normalize_class/1)
      {:error, :nxdomain} -> []
    end
  end

  defp set_response(
         %Message{header: %Header{} = header, question: question} = message,
         answers,
         options
       ) do
    rcode = Keyword.fetch!(options, :rcode)
    aa = Keyword.fetch!(options, :aa)
    authority = Keyword.get(options, :authority, [])
    additional_records = Keyword.get(options, :additional, [])

    opt_additional =
      case query_opt(message) do
        nil -> []
        %OPT{} = client_opt -> [response_opt_for(client_opt, rcode)]
      end

    additional = additional_records ++ opt_additional

    new_header = %Header{
      header
      | qr: 1,
        aa: aa,
        ra: 0,
        # AD (RFC 6840 §5.7) and CD (RFC 4035 §3.2.2) are query-only
        # signals when DNSSEC is not in scope; clear both on every
        # response.
        ad: 0,
        cd: 0,
        rc: rcode,
        anc: length(answers),
        auc: length(authority),
        adc: length(additional)
    }

    %Message{
      message
      | header: new_header,
        question: question,
        answer: answers,
        authority: authority,
        additional: additional
    }
  end

  # Returns the OPT pseudo-RR from the query's additional section, or
  # `nil` if the client did not advertise EDNS0.
  defp query_opt(%Message{additional: additional}) when is_list(additional) do
    Enum.find(additional, fn record -> match?(%OPT{}, record) end)
  end

  defp query_opt(_), do: nil

  # Builds the OPT to include in the response. Echoes the client's DO
  # bit, advertises our own payload size, and copies the lower 4 bits of
  # the rcode into the header (already done) — the upper 8 bits would be
  # split into `extended_rcode` here, but for now no path emits an
  # extended rcode.
  defp response_opt_for(%OPT{dnssec_ok: do_bit}, _rcode) do
    %OPT{
      payload_size: @default_payload_size,
      extended_rcode: 0,
      version: 0,
      dnssec_ok: do_bit,
      z: 0,
      options: []
    }
  end

  defp normalize_class(record) when is_struct(record) do
    case Map.get(record, :class) do
      :internet -> %{record | class: :in}
      _ -> record
    end
  end
end
