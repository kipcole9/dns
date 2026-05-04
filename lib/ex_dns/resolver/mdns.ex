defmodule ExDns.Resolver.MDNS do
  @moduledoc """
  Multicast DNS responder logic (RFC 6762).

  Differs from the unicast resolver in three important ways:

  1. **Scope.** Only answers queries for names that fall under a
     `.local` zone we own. Anything else returns `:no_answer` so the
     listener stays silent (RFC 6762 §6: "the responder MUST NOT
     respond to questions for which it has no answers").
  2. **Response routing.** The response is wrapped in `{:unicast, msg}`
     when the question's QU bit was set, otherwise `{:multicast, msg}`.
     The listener uses this to decide where to send the bytes.
  3. **Header shape.** Per RFC 6762 §18:
     * Transaction ID is set to 0.
     * QR=1, AA=1.
     * Recursion bits cleared.
     * No question is echoed back in multicast responses (the responder
       sends the answer alone). Unicast responses MAY echo the
       question; we choose to echo for compatibility.

  Loopback and conflict-detection (probe / announce, RFC 6762 §8) are
  follow-ups; this module covers the core query-response flow only.

  """

  alias ExDns.Message
  alias ExDns.Message.{Header, Question}
  alias ExDns.Request
  alias ExDns.Storage

  @doc """
  Resolves a Request received via the mDNS listener.

  ### Returns

  * `{:multicast, %Message{}}` — send the response to the multicast group.
  * `{:unicast, %Message{}}` — send the response back to the querier.
  * `:no_answer` — stay silent (the only correct mDNS behaviour when
    we have no records for the question).

  """
  @spec resolve(Request.t()) :: {:unicast, Message.t()} | {:multicast, Message.t()} | :no_answer

  def resolve(%Request{message: %Message{question: nil}}) do
    :no_answer
  end

  def resolve(%Request{message: message}) do
    %Message{question: %Question{} = question} = message

    cond do
      not local_name?(question.host) ->
        :no_answer

      true ->
        case Storage.lookup(question.host, question.type) do
          {:ok, _apex, [_ | _] = records} ->
            # Clear the QU flag from the echoed question — it's a
            # query-only signal and mustn't ride back on the response
            # wire.
            echoed_question = %{question | unicast_response: false}
            response = build_response(message, echoed_question, records)

            if question.unicast_response do
              {:unicast, response}
            else
              {:multicast, response}
            end

          _ ->
            # mDNS: stay silent on NODATA / NXDOMAIN.
            :no_answer
        end
    end
  end

  def resolve(_other), do: :no_answer

  defp local_name?(host) when is_binary(host) do
    host = String.downcase(host, :ascii) |> String.trim_trailing(".")
    host == "local" or String.ends_with?(host, ".local")
  end

  defp local_name?(_), do: false

  defp build_response(%Message{header: %Header{} = original_header} = query, question, records) do
    # We are the authoritative source for these records — set the
    # cache-flush bit (RFC 6762 §10.2) on every answer so receivers
    # drop any stale cached copies before adopting ours.
    records =
      records
      |> Enum.map(&normalize_class/1)
      |> Enum.map(&Map.put(&1, :cache_flush, true))

    new_header = %Header{
      original_header
      | id: 0,
        qr: 1,
        aa: 1,
        tc: 0,
        rd: 0,
        ra: 0,
        ad: 0,
        cd: 0,
        rc: 0,
        qc: 1,
        anc: length(records),
        auc: 0,
        adc: 0
    }

    %Message{
      query
      | header: new_header,
        question: question,
        answer: records,
        authority: [],
        additional: []
    }
  end

  defp normalize_class(record) when is_struct(record) do
    case Map.get(record, :class) do
      :internet -> %{record | class: :in}
      _ -> record
    end
  end
end
