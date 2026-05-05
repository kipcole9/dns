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

  # UPDATE (RFC 2136, opcode 5). Needs source-IP context for
  # the ACL gate, so route the Request directly rather than
  # stripping to Message first.
  def resolve(%Request{message: %Message{header: %Header{qr: 0, oc: 5}} = msg} = request) do
    handle_update(msg, request.source_ip)
  end

  def resolve(%Request{message: message}), do: resolve(message)

  def resolve(%Message{header: %Header{qr: 0, oc: 0}, question: %Question{} = question} = message) do
    answer_query(message, question)
  end

  # UPDATE arriving as a bare Message (no source-IP context).
  # Without a request we can't run the ACL — refuse on principle.
  def resolve(%Message{header: %Header{qr: 0, oc: 5}} = message) do
    set_response(message, [], rcode: 5, aa: 0, authority: [])
  end

  # Inverse query (obsolete) — return NOTIMP.
  def resolve(%Message{header: %Header{qr: 0, oc: 1}} = message) do
    set_response(message, [], rcode: 4, aa: 0, authority: [])
  end

  # NOTIFY (RFC 1996, opcode 4) — acknowledge with NOERROR and
  # trigger an immediate refresh on the matching secondary-zone
  # state machine when one is running. AA is set if we hold the
  # zone (either as primary or secondary).
  def resolve(%Message{header: %Header{qr: 0, oc: 4}, question: question} = message) do
    require Logger

    aa =
      case question do
        %Question{host: host} ->
          Logger.info("Received NOTIFY for #{inspect(host)}")
          # Best-effort kick to the secondary state machine. If
          # we are not a secondary for this zone the call returns
          # `{:error, :no_secondary_for_zone}` and we ignore it.
          _ = ExDns.Zone.Secondary.notify(host)
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

  # CHAOS-class metadata queries (RFC 4892 + de-facto BIND convention).
  # `version.bind`, `hostname.bind`, `id.server`, and `version.server`
  # in class CH are answered from configured server identity strings;
  # all other CHAOS queries return REFUSED.
  defp answer_query(message, %Question{class: :ch} = question) do
    answer_chaos_query(message, question)
  end

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

  # Recognised CHAOS metadata names. We accept the leading-dot variant
  # too because some clients normalise trailing dots inconsistently.
  @chaos_metadata %{
    "version.bind" => :version,
    "version.server" => :version,
    "hostname.bind" => :hostname,
    "id.server" => :hostname
  }

  defp answer_chaos_query(message, %Question{host: qname, type: qtype}) do
    normalised = qname |> String.downcase(:ascii) |> String.trim_trailing(".")

    cond do
      qtype not in [:txt, :any] ->
        # CHAOS class is only defined for TXT in our deployment.
        set_response(message, [], rcode: 4, aa: 0, authority: [])

      Map.has_key?(@chaos_metadata, normalised) ->
        case chaos_value(Map.fetch!(@chaos_metadata, normalised)) do
          nil ->
            set_response(message, [], rcode: 5, aa: 1, authority: [])

          value ->
            answer = [
              %ExDns.Resource.TXT{
                name: normalised,
                ttl: 0,
                class: :ch,
                strings: [value]
              }
            ]

            set_response(message, answer, rcode: 0, aa: 1, authority: [])
        end

      true ->
        set_response(message, [], rcode: 5, aa: 0, authority: [])
    end
  end

  # Resolves the configured value for a CHAOS metadata kind. Operators
  # set them under `:ex_dns, :server_identity, [version: ..., hostname: ...]`.
  # When `:hostname` is unset we fall back to the BEAM node's
  # `:inet.gethostname/0` so the server returns *something* useful out
  # of the box. `:version` defaults to the project version reported in
  # `:application.get_key/2`.
  defp chaos_value(:version) do
    config = Application.get_env(:ex_dns, :server_identity, [])

    case Keyword.get(config, :version) do
      nil ->
        case :application.get_key(:ex_dns, :vsn) do
          {:ok, vsn} -> "ExDns #{List.to_string(vsn)}"
          _ -> "ExDns"
        end

      vsn when is_binary(vsn) ->
        vsn
    end
  end

  defp chaos_value(:hostname) do
    config = Application.get_env(:ex_dns, :server_identity, [])

    case Keyword.get(config, :hostname) do
      nil ->
        case :inet.gethostname() do
          {:ok, host} -> List.to_string(host)
          _ -> nil
        end

      host when is_binary(host) ->
        host
    end
  end

  # IXFR (RFC 1995) — incremental zone transfer.
  #
  # The client puts its current SOA in the query's authority section.
  # We compute the chain of journal entries since that serial and
  # emit the differences-sequence form per RFC 1995 §4. When we
  # cannot build a chain (no journal entries, serial too old, no
  # SOA in the request) we fall back to a full AXFR per RFC 1995
  # §2 ("If the server cannot provide an incremental zone transfer,
  # it should respond with the full zone").
  defp answer_query_authoritative(message, %Question{host: qname, type: :ixfr} = question) do
    qname = String.downcase(qname, :ascii) |> String.trim_trailing(".")

    case ixfr_client_serial(message) do
      {:ok, client_serial} ->
        case build_ixfr_chain(qname, client_serial) do
          {:ok, :up_to_date, current_soa} ->
            # RFC 1995 §2: if the client is already current, return a
            # single SOA so it knows no AXFR is needed.
            set_response(message, [normalize_class(current_soa)],
              rcode: 0,
              aa: 1,
              authority: []
            )

          {:ok, :ixfr, answer_records} ->
            set_response(message, Enum.map(answer_records, &normalize_class/1),
              rcode: 0,
              aa: 1,
              authority: []
            )

          {:error, _reason} ->
            # Fall through to AXFR.
            answer_query_authoritative(message, %{question | type: :axfr})
        end

      {:error, _} ->
        # No SOA in authority section — fall back to AXFR.
        answer_query_authoritative(message, %{question | type: :axfr})
    end
  end

  defp answer_query_authoritative(message, %Question{host: qname, type: :axfr}) do
    qname = String.downcase(qname, :ascii) |> String.trim_trailing(".")
    start_time = System.monotonic_time()

    :telemetry.execute(
      [:ex_dns, :axfr, :transfer, :start],
      %{system_time: System.system_time()},
      %{zone: qname, peer: nil, kind: :axfr}
    )

    {response, axfr_result, record_count} =
      case Storage.find_zone(qname) do
        ^qname ->
          case Storage.dump_zone(qname) do
            {:ok, [%ExDns.Resource.SOA{} = soa | _] = records} ->
              # RFC 5936 §2.2: AXFR response is SOA, all RRs, SOA.
              answer = Enum.map(records ++ [soa], &normalize_class/1)
              {set_response(message, answer, rcode: 0, aa: 1, authority: []), :ok,
               length(answer)}

            {:ok, _} ->
              # Zone exists but has no SOA — refuse.
              {set_response(message, [], rcode: 5, aa: 0, authority: []),
               {:error, :no_soa}, 0}

            {:error, :not_loaded} ->
              {set_response(message, [], rcode: 5, aa: 0, authority: []),
               {:error, :not_loaded}, 0}
          end

        _ ->
          # AXFR can only be served for a zone we are authoritative for at
          # the apex; otherwise REFUSED.
          {set_response(message, [], rcode: 5, aa: 0, authority: []),
           {:error, :not_authoritative}, 0}
      end

    :telemetry.execute(
      [:ex_dns, :axfr, :transfer, :stop],
      %{
        duration: System.monotonic_time() - start_time,
        records: record_count,
        bytes: 0
      },
      %{zone: qname, peer: nil, kind: :axfr, result: axfr_result}
    )

    response
  end

  defp answer_query_authoritative(message, %Question{host: qname, type: :any}) do
    cond do
      refuse_any?() ->
        # RFC 8482 §4.3 — replace the full RRset list with a
        # single synthetic HINFO so the response is small enough
        # to defang DNS amplification.
        synthetic = [
          %ExDns.Resource.HINFO{
            name: qname,
            ttl: 3600,
            class: :in,
            cpu: "RFC8482",
            os: ""
          }
        ]

        set_response(message, synthetic, rcode: 0, aa: 1, authority: [])

      true ->
        do_answer_any(message, qname)
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
        # caching TTL. When DNSSEC is enabled for the zone, the NSEC
        # covering qname is added too so the client can validate the
        # negative answer.
        set_response(message, [],
          rcode: 0,
          aa: 1,
          authority: negative_authority(apex, qname, :nodata)
        )

      {:partial, records, apex} ->
        # We followed at least one CNAME but the chain ended in NODATA
        # for the requested type. Per RFC 1034 §4.3.2, return what we
        # gathered as the answer with rcode = NOERROR; include the SOA
        # in authority for negative caching of the trailing name.
        records = Enum.map(records, &normalize_class/1)
        # The NSEC proof goes at the chain's terminal name.
        terminal = case List.last(records) do
          %ExDns.Resource.CNAME{server: target} -> target
          _ -> qname
        end

        set_response(message, records,
          rcode: 0,
          aa: 1,
          authority: negative_authority(apex, terminal, :nodata)
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
              authority: negative_authority(apex, qname, :nxdomain)
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

  # Returns the negative-response authority section: the apex SOA plus
  # (when DNSSEC is enabled for the zone) the NSEC record proving the
  # negative answer.
  #
  # * `:nodata` — NSEC AT the queried name; its type bitmap omits the
  #   queried qtype, proving "this name exists but lacks that type".
  # * `:nxdomain` — NSEC COVERING the queried name; owner < qname <
  #   next, proving "no name lives in this gap".
  defp negative_authority(apex, qname, kind) do
    soa_authority(apex) ++ nsec_authority(apex, qname, kind)
  end

  defp nsec_authority(apex, qname, kind) do
    case ExDns.DNSSEC.KeyStore.get_signing_key(apex) do
      nil ->
        # Zone is not DNSSEC-signed; no NSEC needed.
        []

      _signing_key ->
        case Storage.dump_zone(apex) do
          {:ok, records} ->
            chain = ExDns.DNSSEC.NSEC.generate(apex, records)
            nsec_for(chain, qname, kind)

          _ ->
            []
        end
    end
  end

  defp nsec_for(chain, qname, :nodata) do
    case ExDns.DNSSEC.NSEC.for_owner(chain, qname) do
      nil -> []
      nsec -> [nsec]
    end
  end

  defp nsec_for(chain, qname, :nxdomain) do
    case ExDns.DNSSEC.NSEC.covering(chain, qname) do
      nil -> []
      nsec -> [nsec]
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

    client_opt = query_opt(message)
    do_bit = match?(%OPT{dnssec_ok: 1}, client_opt)

    answers = if do_bit, do: maybe_sign_records(answers), else: answers
    authority = if do_bit, do: maybe_sign_records(authority), else: authority

    opt_additional =
      case client_opt do
        nil -> []
        %OPT{} -> [response_opt_for(client_opt, rcode)]
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

  # When the inbound query had the DO bit set and we hold signing keys
  # for the zone the records belong to, sign each RRset and append its
  # RRSIG to the section. Records we don't have keys for pass through
  # unchanged. Already-RRSIG records (e.g., served from a pre-signed
  # zone) are left alone.
  defp maybe_sign_records(records) when is_list(records) do
    records
    |> Enum.group_by(&{&1.__struct__ == ExDns.Resource.RRSIG, &1.name, &1.__struct__})
    |> Enum.flat_map(fn
      {{true, _name, _struct}, rrsigs} ->
        # Already-signed RRset; pass through.
        rrsigs

      {{false, name, _struct}, rrset} ->
        rrset_with_signature(name, rrset)
    end)
  end

  defp maybe_sign_records(other), do: other

  defp rrset_with_signature(name, rrset) do
    case Storage.find_zone(name) do
      nil ->
        rrset

      apex ->
        case ExDns.DNSSEC.KeyStore.get_signing_key(apex) do
          nil ->
            rrset

          %{dnskey: dnskey, private_key: private_key} ->
            case ExDns.DNSSEC.Signer.sign_rrset(rrset, dnskey, private_key, signer: apex) do
              {:ok, rrsig} -> rrset ++ [rrsig]
              {:error, _} -> rrset
            end
        end
    end
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

  # ----- ANY-query helpers ----------------------------------------

  defp do_answer_any(message, qname) do
    case Storage.lookup_any(qname) do
      {:ok, _apex, records} ->
        records = Enum.map(records, &normalize_class/1)
        set_response(message, records, rcode: 0, aa: 1, authority: [])

      {:error, :nxdomain} ->
        case Storage.find_zone(qname) do
          nil ->
            set_response(message, [], rcode: 3, aa: 0, authority: [])

          apex ->
            set_response(message, [], rcode: 3, aa: 1,
              authority: negative_authority(apex, qname, :nxdomain))
        end
    end
  end

  defp refuse_any? do
    Application.get_env(:ex_dns, :refuse_any, false)
  end

  # ----- UPDATE handling (RFC 2136) ---------------------------------

  defp handle_update(%Message{question: %Question{host: apex, class: class}} = message, source_ip) do
    apex_norm = String.downcase(apex, :ascii) |> String.trim_trailing(".")

    cond do
      # Step 1 — ACL.
      ExDns.Update.ACL.check(apex_norm, source_ip, nil) == :refuse ->
        update_response(message, 5)

      # Step 2 — we must own the apex (RFC 2136 §3.1: NOTAUTH
      # otherwise).
      Storage.find_zone(apex_norm) != apex_norm ->
        update_response(message, 9)

      true ->
        # Step 3 — prerequisites (Answer section per §2.4).
        with :ok <- ExDns.Update.Prerequisites.check(apex_norm, message.answer, class),
             # Step 4 — apply the updates (Authority section per §2.5).
             :ok <- ExDns.Update.Applier.apply(message.authority, apex_norm, class) do
          update_response(message, 0)
        else
          {:error, rcode} -> update_response(message, rcode)
        end
    end
  end

  defp handle_update(message, _source_ip) do
    update_response(message, 5)
  end

  # Build the standard UPDATE response: header echoed with
  # QR=1, OPCODE=5, the given RCODE, all sections empty.
  defp update_response(%Message{header: %Header{} = header} = message, rcode) do
    %Message{
      message
      | header: %Header{
          header
          | qr: 1,
            aa: 0,
            tc: 0,
            ra: 0,
            ad: 0,
            cd: 0,
            rc: rcode,
            anc: 0,
            auc: 0,
            adc: 0
        },
        answer: [],
        authority: [],
        additional: []
    }
  end

  # ----- IXFR helpers (RFC 1995) ------------------------------------

  # The IXFR query carries the client's current SOA in the authority
  # section (RFC 1995 §3).
  defp ixfr_client_serial(%Message{authority: authority}) when is_list(authority) do
    case Enum.find(authority, &match?(%ExDns.Resource.SOA{}, &1)) do
      %ExDns.Resource.SOA{serial: serial} when is_integer(serial) -> {:ok, serial}
      _ -> {:error, :no_client_soa}
    end
  end

  defp ixfr_client_serial(_), do: {:error, :no_client_soa}

  # Build the IXFR answer-section record list from journal entries.
  # Returns one of:
  #
  #   {:ok, :up_to_date, current_soa}
  #   {:ok, :ixfr, answer_records}
  #   {:error, reason}
  defp build_ixfr_chain(qname, client_serial) do
    with ^qname <- Storage.find_zone(qname),
         {:ok, current_records} <- Storage.dump_zone(qname),
         %ExDns.Resource.SOA{serial: current_serial} = current_soa <-
           Enum.find(current_records, &match?(%ExDns.Resource.SOA{}, &1)) do
      cond do
        client_serial == current_serial ->
          {:ok, :up_to_date, current_soa}

        true ->
          entries = ExDns.Zone.Journal.since(qname, client_serial)
          assemble_ixfr(entries, client_serial, current_serial, current_soa)
      end
    else
      _ -> {:error, :not_authoritative}
    end
  end

  defp assemble_ixfr([], _client_serial, _current_serial, _current_soa) do
    {:error, :no_journal}
  end

  defp assemble_ixfr(entries, client_serial, current_serial, current_soa) do
    chain = Enum.sort_by(entries, & &1.to_serial)

    cond do
      hd(chain).from_serial != client_serial ->
        {:error, :stale_client}

      List.last(chain).to_serial != current_serial ->
        {:error, :journal_behind}

      true ->
        deltas =
          Enum.flat_map(chain, fn entry ->
            old_soa = soa_with_serial(current_soa, entry.from_serial)
            new_soa = soa_with_serial(current_soa, entry.to_serial)
            [old_soa | entry.removed] ++ [new_soa | entry.added]
          end)

        {:ok, :ixfr, [current_soa | deltas] ++ [current_soa]}
    end
  end

  defp soa_with_serial(%ExDns.Resource.SOA{} = soa, serial) do
    %{soa | serial: serial}
  end
end
