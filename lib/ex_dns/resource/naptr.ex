defmodule ExDns.Resource.NAPTR do
  @moduledoc """
  Manages the NAPTR (Naming Authority Pointer) resource record (RFC 3403).

  Type code 35.

  ### NAPTR RDATA format

      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |    ORDER (16 bits)         |
      |  PREFERENCE (16 bits)      |
      |    FLAGS (charstring)      |
      |   SERVICES (charstring)    |
      |   REGEXP  (charstring)     |
      |  REPLACEMENT (name)        |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

  Each `<charstring>` is `<<len::8, data::binary-size(len)>>`.

  """

  @behaviour ExDns.Resource

  defstruct [
    :name,
    :ttl,
    :class,
    :order,
    :preference,
    :flags,
    :services,
    :regexp,
    :replacement
  ]

  alias ExDns.Message

  @impl ExDns.Resource
  def decode(<<order::size(16), preference::size(16), rest::binary>>, message) do
    {flags, rest} = decode_charstring(rest)
    {services, rest} = decode_charstring(rest)
    {regexp, rest} = decode_charstring(rest)
    {:ok, replacement, _} = Message.decode_name(rest, message)

    %__MODULE__{
      order: order,
      preference: preference,
      flags: flags,
      services: services,
      regexp: regexp,
      replacement: replacement
    }
  end

  defp decode_charstring(<<len::size(8), str::binary-size(len), rest::binary>>) do
    {str, rest}
  end

  @impl ExDns.Resource
  def encode(%__MODULE__{
        order: order,
        preference: preference,
        flags: flags,
        services: services,
        regexp: regexp,
        replacement: replacement
      }) do
    <<order::size(16), preference::size(16), encode_charstring(flags)::binary,
      encode_charstring(services)::binary, encode_charstring(regexp)::binary,
      Message.encode_name(replacement)::binary>>
  end

  defp encode_charstring(str) when is_binary(str) do
    <<byte_size(str)::size(8), str::binary>>
  end

  @impl ExDns.Resource
  def format(%__MODULE__{} = resource) do
    [
      ExDns.Resource.format_preamble(resource, "NAPTR"),
      Integer.to_string(resource.order),
      " ",
      Integer.to_string(resource.preference),
      " \"",
      resource.flags,
      "\" \"",
      resource.services,
      "\" \"",
      resource.regexp,
      "\" ",
      ExDns.Resource.to_fqdn(resource.replacement)
    ]
  end

  defimpl ExDns.Resource.Format do
    def format(resource), do: ExDns.Resource.NAPTR.format(resource)
  end
end
