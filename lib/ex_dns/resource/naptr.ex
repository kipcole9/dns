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
  @behaviour ExDns.Resource.JSON

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

  @impl ExDns.Resource.JSON
  def encode_rdata(%__MODULE__{} = naptr) do
    %{
      "order" => naptr.order,
      "preference" => naptr.preference,
      "flags" => naptr.flags,
      "services" => naptr.services,
      "regexp" => naptr.regexp,
      "replacement" => trim_dot(naptr.replacement)
    }
  end

  @impl ExDns.Resource.JSON
  def decode_rdata(%{
        "order" => order,
        "preference" => preference,
        "flags" => flags,
        "services" => services,
        "regexp" => regexp,
        "replacement" => replacement
      })
      when is_integer(order) and is_integer(preference) and is_binary(flags) and
             is_binary(services) and is_binary(regexp) and is_binary(replacement) do
    {:ok,
     %__MODULE__{
       order: order,
       preference: preference,
       flags: flags,
       services: services,
       regexp: regexp,
       replacement: replacement
     }}
  end

  def decode_rdata(_), do: {:error, :invalid_naptr_rdata}

  defp trim_dot(nil), do: nil
  # The literal "." replacement is meaningful in NAPTR — it means
  # "no further replacement; use the regexp". Don't trim it away.
  defp trim_dot("."), do: "."
  defp trim_dot(s) when is_binary(s), do: String.trim_trailing(s, ".")
end
