defmodule ExDns.Message.Answer do
  @moduledoc """
  Decodes and encodes the Answer section of a DNS message.

  The Answer section is a (possibly empty) list of resource records whose
  count is given by the `ANCOUNT` field in the header. The wire format
  for each record is shared with the Authority and Additional sections;
  see `ExDns.Message.RR`.

  """

  alias ExDns.Message
  alias ExDns.Message.RR

  @doc """
  Decodes the Answer section.

  ### Arguments

  * `header` is the already-decoded `%ExDns.Message.Header{}`; only its
    `:anc` field is consulted.

  * `binary` is the message bytes positioned at the first answer record.

  * `message` is the full enclosing DNS message, used for resolving name
    compression pointers.

  ### Returns

  * `{:ok, records, rest}` — `records` is a list of per-type resource
    record structs; `rest` is the remaining bytes after the section.

  """
  def decode(%Message.Header{anc: count}, binary, message) do
    RR.decode_records(count, binary, message)
  end

  @doc """
  Encodes a list of answer records into wire-format bytes.

  Returns the binary; the caller is responsible for setting `ANCOUNT` on
  the header to `length(records)` before encoding the header.

  """
  def encode(records) when is_list(records), do: RR.encode_records(records)

  def encode(nil), do: <<>>
end
