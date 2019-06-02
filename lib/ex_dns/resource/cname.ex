defmodule ExDns.Resource.CNAME do
  @moduledoc """
  Manages the CNAME resource record

  The wire protocol is defined in [RFC1035](https://tools.ietf.org/html/rfc1035#section-3.3.1)

  3.3.1. CNAME RDATA format

      +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
      /                     CNAME                     /
      /                                               /
      +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

  where:

  CNAME           A <domain-name> which specifies the canonical or primary
                  name for the owner.  The owner name is an alias.

  CNAME RRs cause no additional section processing, but name servers may
  choose to restart the query at the canonical name in certain cases.  See
  the description of name server logic in [RFC-1034] for details.

  """

  defstruct [:name, :ttl, :class, :server]
  import ExDns.Resource.Validation
  import ExDns.Resource, only: [class_from: 1]

  def new(resource) do
    resource
    |> validate_integer(:ttl)
    |> validate_class(:class, :internet)
    |> structify_if_valid(__MODULE__)
  end

  @preamble ExDns.Resource.preamble_format()
  def format(%__MODULE__{} = resource) do
    format_string = [@preamble | '~-20s']

    format_string
    |> :io_lib.format([resource.name, resource.ttl, class_from(resource.class), resource.server])
    |> List.flatten()
    |> List.to_string()
  end

  defimpl ExDns.Resource.Format do
    def format(resource) do
      __MODULE__.format(resource)
    end
  end
end
