defmodule ExDns.EDNSPadding do
  @moduledoc """
  EDNS(0) Padding option (RFC 7830 / RFC 8467).

  Pads DNS responses on confidential transports (DoT, DoH) so an
  on-path observer can't infer which name was queried from the
  response size. Useless for plain UDP/TCP DNS — the question is
  visible there anyway — so this is wired only on the encrypted
  paths.

  ## Strategy

  RFC 8467 §4.2 "Block-Length Padding" with a 468-byte block: pad
  every response up to the next multiple of 468 bytes. That's a
  good privacy/overhead trade-off for typical DNS sizes (most
  responses fit in one block).

  ## When to pad

  RFC 8467 §6.1 mandates: pad **only** when the corresponding
  request carried the Padding option. The listener checks this
  with `requested?/1` before calling `pad/2`.

  ## How to pad

  1. Encode the response to find its current wire size.
  2. Compute padding length = `block_length - rem(size, block_length)`,
     accounting for the 4-byte option header (code + length fields).
  3. Insert/replace option `12` in the OPT record with that many
     zero bytes.
  """

  alias ExDns.Message
  alias ExDns.Resource.OPT

  @padding_option_code 12
  @default_block_length 468

  @doc """
  Returns the EDNS Padding option code (`12`).

  ### Examples

      iex> ExDns.EDNSPadding.option_code()
      12

  """
  @spec option_code() :: 12
  def option_code, do: @padding_option_code

  @doc """
  Did the request advertise EDNS Padding support?

  Per RFC 8467 §6.1, a server may pad a response only when the
  corresponding request carried the Padding option (irrespective
  of how many bytes that request asked for).

  ### Arguments

  * `request` is the inbound `%ExDns.Message{}`.

  ### Returns

  * `true` when the request's additional section contains an OPT
    record that carries option code `12`.

  * `false` otherwise.

  ### Examples

      iex> ExDns.EDNSPadding.requested?(%ExDns.Message{
      ...>   header: %ExDns.Message.Header{id: 0, qr: 0, oc: 0, aa: 0, tc: 0, rd: 0,
      ...>                                  ra: 0, ad: 0, cd: 0, rc: 0,
      ...>                                  qc: 1, anc: 0, auc: 0, adc: 0},
      ...>   question: %ExDns.Message.Question{host: "x", type: :a, class: :in},
      ...>   answer: [], authority: [], additional: []
      ...> })
      false

  """
  @spec requested?(Message.t()) :: boolean()
  def requested?(%Message{additional: additional}) when is_list(additional) do
    case Enum.find(additional, &match?(%OPT{}, &1)) do
      %OPT{options: options} -> List.keymember?(options, @padding_option_code, 0)
      _ -> false
    end
  end

  def requested?(_), do: false

  @doc """
  Pad `response` so its encoded wire form is a multiple of
  `block_length` bytes.

  ### Arguments

  * `response` is the resolver's response `%ExDns.Message{}`.

  * `block_length` is the padding block size in bytes. Defaults to
    `468` per RFC 8467 §4.2.

  ### Returns

  * The (possibly modified) response message.

  * If the response has no OPT record we return it unchanged —
    padding without an OPT pseudo-RR isn't representable.

  ### Examples

      iex> response = %ExDns.Message{
      ...>   header: %ExDns.Message.Header{id: 0, qr: 1, oc: 0, aa: 1, tc: 0, rd: 0,
      ...>                                  ra: 0, ad: 0, cd: 0, rc: 0,
      ...>                                  qc: 1, anc: 0, auc: 0, adc: 1},
      ...>   question: %ExDns.Message.Question{host: "x", type: :a, class: :in},
      ...>   answer: [], authority: [],
      ...>   additional: [%ExDns.Resource.OPT{payload_size: 4096, options: []}]
      ...> }
      iex> padded = ExDns.EDNSPadding.pad(response, 64)
      iex> rem(byte_size(ExDns.Message.encode(padded)), 64)
      0

  """
  @spec pad(Message.t(), pos_integer()) :: Message.t()
  def pad(%Message{} = response, block_length \\ @default_block_length)
      when is_integer(block_length) and block_length > 0 do
    case opt_index(response) do
      nil ->
        response

      index ->
        # Encode without padding to measure, then compute the
        # required option-data length so the *re*-encoded size is
        # a multiple of block_length. The 4-byte difference
        # (option code + option length) is folded into the target.
        {%OPT{} = opt, rest} = pop_opt(response, index)
        cleared_opt = %OPT{opt | options: List.keydelete(opt.options, @padding_option_code, 0)}
        candidate = %Message{response | additional: rest ++ [cleared_opt]}

        current_size = byte_size(Message.encode(candidate))
        target = ceil_to_block(current_size + 4, block_length)
        pad_length = target - current_size - 4

        padded_opt = %OPT{
          cleared_opt
          | options: cleared_opt.options ++ [{@padding_option_code, :binary.copy(<<0>>, pad_length)}]
        }

        %Message{candidate | additional: rest ++ [padded_opt]}
    end
  end

  defp opt_index(%Message{additional: additional}) do
    Enum.find_index(additional, &match?(%OPT{}, &1))
  end

  defp pop_opt(%Message{additional: additional}, index) do
    {before_opt, [opt | after_opt]} = Enum.split(additional, index)
    {opt, before_opt ++ after_opt}
  end

  defp ceil_to_block(size, block_length) do
    case rem(size, block_length) do
      0 -> size
      r -> size + (block_length - r)
    end
  end
end
