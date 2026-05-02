defmodule ExDns.Message.Additional do
  @moduledoc """
  Decodes and encodes the Additional section of a DNS message.

  The Additional section is a (possibly empty) list of resource records
  whose count is given by the `ARCOUNT` field in the header. The wire
  format for each record is shared with the Answer and Authority
  sections; see `ExDns.Message.RR`.

  """

  alias ExDns.Message
  alias ExDns.Message.RR

  @doc """
  Decodes the Additional section.

  Returns `{:ok, records, rest}`.

  """
  def decode(%Message.Header{adc: count}, binary, message) do
    RR.decode_records(count, binary, message)
  end

  @doc """
  Encodes a list of additional records into wire-format bytes.
  """
  def encode(records) when is_list(records), do: RR.encode_records(records)

  def encode(nil), do: <<>>
end
