defmodule ExDns.Resource.A do
  defstruct [:name, :ttl, :class, :ipv4]
  import ExDns.Resource.Validation
  import ExDns.Resource, only: [class_from: 1]
  alias ExDns.Inet.Ipv4

  def new(resource) do
    resource
    |> validate_ipv4(:ipv4)
    |> validate_integer(:ttl)
    |> validate_class(:class, :internet)
    |> structify_if_valid(__MODULE__)
  end

  @preamble ExDns.Resource.preamble_format
  def format(resource) do
    format_string = @preamble ++ '~-20s'

    format_string
    |> :io_lib.format([resource.name, resource.ttl, class_from(resource.class),
        Ipv4.to_string(resource.ipv4)])
  end

  defimpl ExDns.Resource.Format do
    ExDns.Resource.format(resource)
  end


  # This is the wire protocol format taken from
  # 3.4.1. A RDATA format
  #
  #     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  #     |                    ADDRESS                    |
  #     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  #
  # where:
  #
  # ADDRESS         A 32 bit Internet address.
  #
  # Hosts that have multiple Internet addresses will have multiple A
  # records.
  #
  # A records cause no additional section processing.  The RDATA section of
  # an A line in a master file is an Internet address expressed as four
  # decimal numbers separated by dots without any imbedded spaces (e.g.,
  # "10.2.0.52" or "192.0.5.6").
end