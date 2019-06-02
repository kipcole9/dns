defmodule ExDns.Resource.A do
  @moduledoc """
  Manages the A resource record

  The wire protocol is defined in [RFC1035](https://tools.ietf.org/html/rfc1035#section-3.4.1)

  3.4.1. A RDATA format

      +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
      |                    ADDRESS                    |
      +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

  where:

  ADDRESS         A 32 bit Internet address.

  Hosts that have multiple Internet addresses will have multiple A
  records.

  A records cause no additional section processing.  The RDATA section of
  an A line in a master file is an Internet address expressed as four
  decimal numbers separated by dots without any imbedded spaces (e.g.,
  "10.2.0.52" or "192.0.5.6").

  """
  defstruct [:name, :ttl, :class, :ipv4]
  import ExDns.Resource.Validation
  import ExDns.Resource, only: [class_from: 1]
  alias ExDns.Inet.Ipv4

  @doc """
  Returns an A resource from a keyword list

  """
  def new(resource) when is_list(resource) do
    resource
    |> validate_ipv4(:ipv4)
    |> validate_integer(:ttl)
    |> validate_class(:class, :internet)
    |> structify_if_valid(__MODULE__)
  end

  def encode(%__MODULE__{} = resource) do
    %{name: name, ttl: ttl, class: class, ipv4: ipv4} = resource
    rdata = << Ipv4.to_integer(ipv4) :: bytes-size(4) >>
    rdlength = << byte_size(rdata) :: unsigned-integer-size(32) >>

    << Message.encode_name(name), Message.encode_class(class), Message.encode_type(type),
    rdlength, rdata >>
  end

  @preamble ExDns.Resource.preamble_format()
  def format(%__MODULE__{} = resource) do
    format_string = [@preamble | '~-20s']

    format_string
    |> :io_lib.format([
      resource.name,
      resource.ttl,
      class_from(resource.class),
      Ipv4.to_string(resource.ipv4)
    ])
  end

  defimpl ExDns.Resource.Format do
    def format(resource) do
      ExDns.Resource.A.format(resource)
    end

    def encode(%ExDns.Resource.A{} = resource) do
      ExDns.Resource.A.encode(resource)
    end
  end
end
