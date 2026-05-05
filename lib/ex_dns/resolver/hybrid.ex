defmodule ExDns.Resolver.Hybrid do
  @moduledoc """
  Hybrid resolver — answers authoritatively for zones we host, then
  falls through to recursive resolution when:

  * the client set the RD (Recursion Desired) bit on the query, AND
  * the qname does not fall under any zone we host, AND
  * recursion is enabled in configuration.

  When recursion is disabled (`Application.get_env(:ex_dns, :recursion,
  false)` returns false), this module behaves identically to
  `ExDns.Resolver.Default`.

  """

  alias ExDns.Message
  alias ExDns.Message.{Header, Question}
  alias ExDns.Recursor.Iterator
  alias ExDns.Request
  alias ExDns.Resolver.Default
  alias ExDns.Storage

  @doc """
  Resolves `query`. If we are authoritative (or the client did not
  request recursion), the result is whatever `ExDns.Resolver.Default`
  produces. Otherwise, recursion kicks in.
  """
  @spec resolve(Message.t() | Request.t()) :: Message.t()
  def resolve(%Request{message: message}), do: resolve(message)

  def resolve(%Message{} = query) do
    if should_recurse?(query) do
      recurse(query)
    else
      Default.resolve(query)
    end
  end

  defp should_recurse?(%Message{
         header: %Header{qr: 0, oc: 0, rd: 1},
         question: %Question{host: qname}
       }) do
    Application.get_env(:ex_dns, :recursion, false) and Storage.find_zone(qname) == nil
  end

  defp should_recurse?(_), do: false

  defp recurse(%Message{header: %Header{} = header, question: %Question{host: qname, type: qtype}} = query) do
    do_bit = client_do_bit?(query)

    result =
      if do_bit do
        Iterator.resolve_validated(qname, qtype)
      else
        case Iterator.resolve(qname, qtype) do
          {:ok, records} -> {:ok, records, :insecure}
          other -> other
        end
      end

    case result do
      {:ok, records, status} ->
        # Per RFC 4035 §3.2.3, AD is set only when the response is
        # both DO-aware AND verifiably secure. We never set AD on
        # responses to clients that didn't ask for DNSSEC.
        ad = if do_bit and status == :secure, do: 1, else: 0

        new_header = %Header{
          header
          | qr: 1,
            aa: 0,
            ra: 1,
            ad: ad,
            cd: 0,
            rc: 0,
            anc: length(records),
            auc: 0,
            adc: response_adc(query)
        }

        response = %Message{
          query
          | header: new_header,
            answer: records,
            authority: [],
            additional: response_additional(query)
        }

        attach_validation_ede(response, status)

      {:error, :nxdomain} ->
        respond(query, [], 3)

      {:error, _other} ->
        # SERVFAIL on transport / depth / time errors.
        respond(query, [], 2)
        |> ExDns.ExtendedDNSErrors.PostProcess.attach([
          {:no_reachable_authority, "iterator failed to resolve"}
        ])
    end
  end

  # Attach an EDE option per DNSSEC validation outcome. RFC 8914
  # §4 reserves codes for the failure modes the validator
  # surfaces; `:secure` and `:insecure` carry no EDE since
  # there's nothing for the client to be informed about.
  defp attach_validation_ede(response, :bogus) do
    ExDns.ExtendedDNSErrors.PostProcess.attach(response, [
      {:dnssec_bogus, "DNSSEC validation failed"}
    ])
  end

  defp attach_validation_ede(response, :indeterminate) do
    ExDns.ExtendedDNSErrors.PostProcess.attach(response, [
      {:dnssec_indeterminate, "Could not build a validation chain"}
    ])
  end

  defp attach_validation_ede(response, _status), do: response

  defp client_do_bit?(%Message{additional: additional}) when is_list(additional) do
    Enum.any?(additional, fn
      %ExDns.Resource.OPT{dnssec_ok: 1} -> true
      _ -> false
    end)
  end

  defp client_do_bit?(_), do: false

  defp respond(%Message{header: %Header{} = header} = query, answers, rcode) do
    %Message{
      query
      | header: %Header{
          header
          | qr: 1,
            aa: 0,
            ra: 1,
            ad: 0,
            cd: 0,
            rc: rcode,
            anc: length(answers),
            auc: 0,
            adc: response_adc(query)
        },
        answer: answers,
        authority: [],
        additional: response_additional(query)
    }
  end

  defp response_adc(query), do: length(response_additional(query))

  defp response_additional(%Message{additional: additional}) when is_list(additional) do
    case Enum.find(additional, &match?(%ExDns.Resource.OPT{}, &1)) do
      nil -> []
      %ExDns.Resource.OPT{dnssec_ok: do_bit} ->
        [%ExDns.Resource.OPT{
          payload_size: 1232,
          extended_rcode: 0,
          version: 0,
          dnssec_ok: do_bit,
          z: 0,
          options: []
        }]
    end
  end

  defp response_additional(_), do: []
end
