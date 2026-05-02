defmodule ExDns.Message.Authority do
  @moduledoc """
  Decodes and encodes the Authority section of a DNS message.

  The Authority section is a (possibly empty) list of resource records
  whose count is given by the `NSCOUNT` field in the header. The wire
  format for each record is shared with the Answer and Additional
  sections; see `ExDns.Message.RR`.

  """

  alias ExDns.Message
  alias ExDns.Message.RR

  @doc """
  Decodes the Authority section.

  Returns `{:ok, records, rest}`.

  """
  def decode(%Message.Header{auc: count}, binary, message) do
    RR.decode_records(count, binary, message)
  end

  @doc """
  Encodes a list of authority records into wire-format bytes.
  """
  def encode(records) when is_list(records), do: RR.encode_records(records)

  def encode(nil), do: <<>>
end
