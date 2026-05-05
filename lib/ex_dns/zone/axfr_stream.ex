defmodule ExDns.Zone.AxfrStream do
  @moduledoc """
  RFC 5936 §2.2 — split a single AXFR response into a stream of
  TCP messages so each fits comfortably under the 64 KiB DNS
  message limit.

  Without chunking, AXFR for a zone with thousands of records
  produces a single Message struct that may exceed 64 KiB when
  encoded — the TCP framing then refuses it. RFC 5936 §2.2
  explicitly allows the server to split the response into
  multiple messages, each containing a subset of the answer
  records, with the question echoed in each (per §2.2.1).

  ## Boundary rules

  * The first message MUST start with the apex SOA (already true
    for AXFR responses produced by the authoritative resolver).
  * The last message MUST end with the same SOA.
  * Intermediate messages carry pure record runs.
  * Every message echoes the original Question section.
  * Header flags: every message has `QR=1`, `AA=1`, `OPCODE=0`,
    `RC=0`. Other bits per RFC 5936 §2.2.1.

  ## Default chunk size

  100 records per message is the default — small enough that
  encoded bytes stay well under 64 KiB even with verbose RR
  types (TXT, RRSIG), large enough that even a 50K-record zone
  finishes in 500 messages without per-message overhead
  dominating.
  """

  alias ExDns.Message
  alias ExDns.Message.Header

  @default_chunk_size 100

  @doc """
  Chunk an AXFR response Message into a list of streamed
  messages. The input is exactly what `Resolver.Default.resolve/1`
  produces for an `:axfr` query — header.aa=1, the question
  echoed, the answer section starting and ending with the apex
  SOA.

  ### Arguments

  * `response` — the AXFR response Message.

  * `options` — keyword list:

  ### Options

  * `:chunk_size` — records per intermediate message. Defaults
    to `100`.

  ### Returns

  * `[Message.t()]` — at least one message. Single-message zones
    return `[response]` unchanged.

  ### Examples

      iex> alias ExDns.Message
      iex> alias ExDns.Message.{Header, Question}
      iex> response = %Message{
      ...>   header: %Header{id: 1, qr: 1, oc: 0, aa: 1, tc: 0, rd: 0, ra: 0,
      ...>                    ad: 0, cd: 0, rc: 0, qc: 1, anc: 0, auc: 0, adc: 0},
      ...>   question: %Question{host: "x", type: :axfr, class: :in},
      ...>   answer: [], authority: [], additional: []
      ...> }
      iex> [^response] = ExDns.Zone.AxfrStream.chunk(response)
      [response]

  """
  @spec chunk(Message.t(), keyword()) :: [Message.t()]
  def chunk(%Message{answer: answer} = response, options \\ []) do
    chunk_size = Keyword.get(options, :chunk_size, @default_chunk_size)

    cond do
      length(answer) <= chunk_size ->
        [response]

      true ->
        do_chunk(response, chunk_size)
    end
  end

  defp do_chunk(%Message{answer: answer} = response, chunk_size) do
    answer
    |> Enum.chunk_every(chunk_size)
    |> Enum.map(fn group -> message_for_chunk(response, group) end)
  end

  defp message_for_chunk(%Message{header: %Header{} = header} = template, records) do
    %Message{
      template
      | header: %Header{
          header
          | qr: 1,
            aa: 1,
            anc: length(records),
            auc: 0,
            adc: 0
        },
        answer: records,
        # RFC 5936 §2.2.1: intermediate messages MUST have empty
        # Authority + Additional sections. The first/last share
        # the same shape.
        authority: [],
        additional: []
    }
  end
end
