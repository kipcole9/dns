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
    case Iterator.resolve(qname, qtype) do
      {:ok, records} ->
        new_header = %Header{
          header
          | qr: 1,
            aa: 0,
            ra: 1,
            ad: 0,
            cd: 0,
            rc: 0,
            anc: length(records),
            auc: 0,
            adc: response_adc(query)
        }

        %Message{
          query
          | header: new_header,
            answer: records,
            authority: [],
            additional: response_additional(query)
        }

      {:error, :nxdomain} ->
        respond(query, [], 3)

      {:error, _other} ->
        # SERVFAIL on transport / depth / time errors.
        respond(query, [], 2)
    end
  end

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
